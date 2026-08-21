use thiserror::Error;

use crate::il::common::{
    IlBlockArgId, IlBlockId, IlCsr, IlDominance, IlEdgeKinds, IlError, IlOpId, IlSsaDef, IlValueId,
    SsaIl,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SsaVerifyError {
    #[error("block {block} argument count mismatch: expected {expected}, found {found}")]
    BlockArgCount {
        block: u32,
        expected: usize,
        found: usize,
    },
    #[error("SSA memory-domain table contains a duplicate address space")]
    DuplicateMemoryDomain,
    #[error("SSA edge-argument table count mismatch: expected {expected}, found {found}")]
    EdgeArgTableCount { expected: usize, found: usize },
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("SSA operation {operation} has invalid block placement")]
    InvalidOpPlacement { operation: u32 },
    #[error("SSA value has an invalid definition")]
    InvalidValueDef,
    #[error(
        "SSA value {value} does not dominate edge from block {predecessor} to block {successor}"
    )]
    NonDominatingEdgeArg {
        value: u32,
        predecessor: u32,
        successor: u32,
    },
    #[error("SSA value {value} does not dominate use by operation {user}")]
    NonDominatingUse { value: u32, user: u32 },
}

pub struct SsaVerifier<'a, I> {
    ir: &'a I,
}

impl<'a, I> SsaVerifier<'a, I>
where
    I: SsaIl,
{
    pub const fn new(ir: &'a I) -> Self {
        Self { ir }
    }

    pub fn verify_memory_domains(&self) -> Result<(), SsaVerifyError> {
        for index in 0..self.ir.memory_domain_count() {
            let Some(space) = self.ir.memory_domain_space(index) else {
                return Err(
                    IlError::range_out_of_bounds(index + 1, self.ir.memory_domain_count()).into(),
                );
            };
            if (0..index).any(|existing| self.ir.memory_domain_space(existing) == Some(space)) {
                return Err(SsaVerifyError::DuplicateMemoryDomain);
            }
        }

        Ok(())
    }

    pub fn verify_edge_args(&self) -> Result<(), SsaVerifyError> {
        if self.ir.edge_args().len() != self.ir.graph().successors().len() {
            return Err(SsaVerifyError::EdgeArgTableCount {
                expected: self.ir.graph().successors().len(),
                found: self.ir.edge_args().len(),
            });
        }

        for range in self.ir.edge_args() {
            range.verify_bounds(self.ir.edge_arg_values().len())?;
        }

        for value in self.ir.edge_arg_values() {
            if value.index() >= self.ir.value_count() {
                return Err(
                    IlError::range_out_of_bounds(value.index(), self.ir.value_count()).into(),
                );
            }
        }

        Ok(())
    }

    pub fn verify_uses<E>(
        &self,
        mut verify_edge_arg: impl FnMut(IlValueId, IlValueId) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<SsaVerifyError>,
    {
        if self.ir.graph().blocks().is_empty() {
            return self.verify_linear_uses().map_err(E::from);
        }

        let dominance = self.ir.analyse::<IlDominance>();
        let operation_blocks = self.ir.graph().op_blocks(self.ir.op_count());

        self.verify_edge_uses(&dominance, &operation_blocks, &mut verify_edge_arg)?;

        for operation_index in 0..self.ir.op_count() {
            let operation = IlOpId::try_from_index(operation_index)
                .map_err(SsaVerifyError::from)
                .map_err(E::from)?;
            let Some(user_block) = operation_blocks[operation_index] else {
                return Err(E::from(SsaVerifyError::InvalidOpPlacement {
                    operation: operation.value(),
                }));
            };

            if !dominance.is_reachable(user_block) {
                self.verify_operands_precede(operation, operation_index)
                    .map_err(E::from)?;
                continue;
            }

            let operands = self.ir.op_operands(operation).ok_or_else(|| {
                E::from(SsaVerifyError::InvalidOpPlacement {
                    operation: operation.value(),
                })
            })?;
            for &operand in operands {
                if !self
                    .value_dominates_op(
                        operand,
                        user_block,
                        operation_index,
                        &dominance,
                        &operation_blocks,
                    )
                    .map_err(E::from)?
                {
                    return Err(E::from(SsaVerifyError::NonDominatingUse {
                        value: operand.value(),
                        user: operation.value(),
                    }));
                }
            }
        }

        Ok(())
    }

    fn verify_edge_uses<E>(
        &self,
        dominance: &IlDominance,
        operation_blocks: &[Option<IlBlockId>],
        verify_edge_arg: &mut impl FnMut(IlValueId, IlValueId) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<SsaVerifyError>,
    {
        let block_args = IlCsr::try_from_entries(
            self.ir.graph().blocks().len(),
            (0..self.ir.block_arg_count()).map(|index| {
                let arg = IlBlockArgId::try_from_index(index)
                    .expect("block argument count fits the identifier space");
                (
                    self.ir
                        .block_arg_block(arg)
                        .map_or(self.ir.graph().blocks().len(), |block| block.index()),
                    index,
                )
            }),
        )
        .map_err(SsaVerifyError::from)
        .map_err(E::from)?;

        for (predecessor_index, predecessor) in self.ir.graph().blocks().iter().enumerate() {
            let predecessor_id = IlBlockId::try_from_index(predecessor_index)
                .map_err(SsaVerifyError::from)
                .map_err(E::from)?;

            for (successor_offset, successor) in predecessor
                .successors()
                .checked_slice(self.ir.graph().successors())
                .map_err(SsaVerifyError::from)
                .map_err(E::from)?
                .iter()
                .enumerate()
            {
                let edge = predecessor.successors().start() + successor_offset;
                let args = self
                    .ir
                    .edge_args()
                    .get(edge)
                    .and_then(|range| range.checked_slice(self.ir.edge_arg_values()).ok())
                    .ok_or_else(|| {
                        E::from(SsaVerifyError::BlockArgCount {
                            block: successor.value(),
                            expected: block_args.row(successor.index()).len(),
                            found: 0,
                        })
                    })?;
                let block_args = block_args.row(successor.index());
                if args.len() != block_args.len() {
                    return Err(E::from(SsaVerifyError::BlockArgCount {
                        block: successor.value(),
                        expected: block_args.len(),
                        found: args.len(),
                    }));
                }

                for (&value, &arg_index) in args.iter().zip(block_args) {
                    let arg = IlBlockArgId::try_from_index(arg_index)
                        .map_err(SsaVerifyError::from)
                        .map_err(E::from)?;
                    let destination = self
                        .ir
                        .block_arg_value(arg)
                        .ok_or_else(|| E::from(SsaVerifyError::InvalidValueDef))?;
                    if self.ir.value_width(value) != self.ir.block_arg_width(arg) {
                        return Err(E::from(SsaVerifyError::Il(IlError::width_mismatch(
                            I::FORM,
                        ))));
                    }
                    verify_edge_arg(value, destination)?;

                    if dominance.is_reachable(predecessor_id)
                        && !self
                            .value_dominates_edge(
                                value,
                                predecessor_id,
                                dominance,
                                operation_blocks,
                            )
                            .map_err(E::from)?
                    {
                        return Err(E::from(SsaVerifyError::NonDominatingEdgeArg {
                            value: value.value(),
                            predecessor: predecessor_id.value(),
                            successor: successor.value(),
                        }));
                    }
                }
            }
        }

        Ok(())
    }

    fn verify_linear_uses(&self) -> Result<(), SsaVerifyError> {
        for operation_index in 0..self.ir.op_count() {
            let operation = IlOpId::try_from_index(operation_index)?;
            self.verify_operands_precede(operation, operation_index)?;
        }

        Ok(())
    }

    fn verify_operands_precede(
        &self,
        operation: IlOpId,
        operation_index: usize,
    ) -> Result<(), SsaVerifyError> {
        let operands =
            self.ir
                .op_operands(operation)
                .ok_or(SsaVerifyError::InvalidOpPlacement {
                    operation: operation.value(),
                })?;
        for &operand in operands {
            let definition = self
                .ir
                .value_definition(operand)
                .ok_or(SsaVerifyError::InvalidValueDef)?;
            if let IlSsaDef::Op(definition) = definition
                && definition.index() >= operation_index
            {
                return Err(SsaVerifyError::NonDominatingUse {
                    value: operand.value(),
                    user: operation.value(),
                });
            }
        }

        Ok(())
    }

    fn value_dominates_op(
        &self,
        value: IlValueId,
        user_block: IlBlockId,
        user_operation: usize,
        dominance: &IlDominance,
        operation_blocks: &[Option<IlBlockId>],
    ) -> Result<bool, SsaVerifyError> {
        match self
            .ir
            .value_definition(value)
            .ok_or(SsaVerifyError::InvalidValueDef)?
        {
            IlSsaDef::Op(operation) => {
                let definition_operation = operation.index();
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    return Err(SsaVerifyError::InvalidOpPlacement {
                        operation: operation.value(),
                    });
                };

                if definition_block == user_block {
                    Ok(definition_operation < user_operation)
                } else {
                    Ok(dominance.dominates(definition_block, user_block))
                }
            }
            IlSsaDef::BlockArg(arg) => {
                let block = self
                    .ir
                    .block_arg_block(arg)
                    .ok_or(SsaVerifyError::InvalidValueDef)?;
                Ok(dominance.dominates(block, user_block))
            }
        }
    }

    fn value_dominates_edge(
        &self,
        value: IlValueId,
        predecessor: IlBlockId,
        dominance: &IlDominance,
        operation_blocks: &[Option<IlBlockId>],
    ) -> Result<bool, SsaVerifyError> {
        match self
            .ir
            .value_definition(value)
            .ok_or(SsaVerifyError::InvalidValueDef)?
        {
            IlSsaDef::Op(operation) => {
                let definition_operation = operation.index();
                let Some(definition_block) = operation_blocks
                    .get(definition_operation)
                    .copied()
                    .flatten()
                else {
                    return Err(SsaVerifyError::InvalidOpPlacement {
                        operation: operation.value(),
                    });
                };

                Ok(definition_block == predecessor
                    || dominance.dominates(definition_block, predecessor))
            }
            IlSsaDef::BlockArg(arg) => {
                let block = self
                    .ir
                    .block_arg_block(arg)
                    .ok_or(SsaVerifyError::InvalidValueDef)?;
                Ok(dominance.dominates(block, predecessor))
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StructureError {
    #[error("block source count mismatch: expected {expected}, found {found}")]
    BlockSourceCount { expected: usize, found: usize },
    #[error("block {block} has duplicate successor {successor}")]
    DuplicateSuccessor { block: u32, successor: u32 },
    #[error("edge kind count mismatch: expected {expected}, found {found}")]
    EdgeKindCount { expected: usize, found: usize },
    #[error("block {block} edge {edge} has kinds {kinds:?} its terminator cannot produce")]
    EdgeKindMismatch {
        block: u32,
        edge: usize,
        kinds: IlEdgeKinds,
    },
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("block {block} operation range overlaps at operation {operation}")]
    OverlappingBlockOps { block: u32, operation: usize },
    #[error("parent spans overlap at destination node {node}")]
    OverlappingParentSpan { node: usize },
    #[error("source spans overlap at destination node {node}")]
    OverlappingSourceSpan { node: usize },
}

pub trait StructureVerifierError: From<IlError> {
    fn structure(error: StructureError) -> Self;

    fn from_structure(error: StructureError) -> Self {
        match error {
            StructureError::Il(error) => error.into(),
            error => Self::structure(error),
        }
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;
    use crate::il::common::{
        ControlFlowIl, IlArtefact, IlBlock, IlBlockArgId, IlBlockProperties, IlGraph, IlIndexRange,
        IlMetadata, IlParentSpan, IlSourceSpan,
    };
    use crate::ir::{Address, FunctionId};
    use crate::storage::segments::space::AddressSpaceId;
    use crate::types::EstimateSize;

    struct EdgeArgFixture {
        metadata: IlMetadata,
        graph: IlGraph,
        edge_args: Vec<IlIndexRange>,
    }

    impl EstimateSize for EdgeArgFixture {
        fn estimate_size(&self) -> usize {
            size_of::<Self>()
        }
    }

    impl IlArtefact for EdgeArgFixture {
        const FORM_IDENTIFIER: &str = "test.edge-args";

        fn metadata(&self) -> &IlMetadata {
            &self.metadata
        }
    }

    impl ControlFlowIl for EdgeArgFixture {
        fn graph(&self) -> &IlGraph {
            &self.graph
        }
    }

    impl SsaIl for EdgeArgFixture {
        fn value_count(&self) -> usize {
            0
        }

        fn value_definition(&self, _value: IlValueId) -> Option<IlSsaDef> {
            None
        }

        fn value_width(&self, _value: IlValueId) -> Option<u32> {
            None
        }

        fn block_arg_count(&self) -> usize {
            0
        }

        fn block_arg_block(&self, _arg: IlBlockArgId) -> Option<IlBlockId> {
            None
        }

        fn block_arg_value(&self, _arg: IlBlockArgId) -> Option<IlValueId> {
            None
        }

        fn block_arg_width(&self, _arg: IlBlockArgId) -> Option<u32> {
            None
        }

        fn op_count(&self) -> usize {
            0
        }

        fn op_operands(&self, _operation: IlOpId) -> Option<&[IlValueId]> {
            None
        }

        fn edge_args(&self) -> &[IlIndexRange] {
            &self.edge_args
        }

        fn edge_arg_values(&self) -> &[IlValueId] {
            &[]
        }

        fn memory_domain_count(&self) -> usize {
            0
        }

        fn memory_domain_space(&self, _index: usize) -> Option<AddressSpaceId> {
            None
        }
    }

    #[test]
    fn ssa_verifier_reports_the_global_edge_arg_table_count() {
        let block = IlBlockId::try_from_index(0).unwrap();
        let ir = EdgeArgFixture {
            metadata: IlMetadata::new(FunctionId::default(), 0),
            graph: IlGraph::new(
                vec![IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::empty(),
                )],
                vec![block],
                vec![IlEdgeKinds::UNCONDITIONAL],
            ),
            edge_args: Vec::new(),
        };

        assert_eq!(
            SsaVerifier::new(&ir).verify_edge_args(),
            Err(SsaVerifyError::EdgeArgTableCount {
                expected: 1,
                found: 0,
            })
        );
    }

    #[test]
    fn structural_verifier_rejects_out_of_range_source_span() {
        let span = IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            Address::new(AddressSpaceId::new(1), 0),
            0,
            1,
        );

        assert!(matches!(
            IlSourceSpan::verify(&[span], 1),
            Err(StructureError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn structural_verifier_rejects_overlapping_source_spans() {
        let first = IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            Address::new(AddressSpaceId::new(1), 0),
            0,
            1,
        );
        let second = IlSourceSpan::new(
            IlIndexRange::new(1, 3).unwrap(),
            Address::new(AddressSpaceId::new(1), 4),
            0,
            1,
        );

        assert!(matches!(
            IlSourceSpan::verify(&[first, second], 8),
            Err(StructureError::OverlappingSourceSpan { .. })
        ));
    }

    #[test]
    fn structural_verifier_rejects_out_of_range_parent_span() {
        let span = IlParentSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::new(0, 1).unwrap(),
        );

        assert!(matches!(
            IlParentSpan::verify(&[span], 1),
            Err(StructureError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }
}
