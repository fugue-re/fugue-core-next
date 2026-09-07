use thiserror::Error;

use crate::il::common::verify::{StructureError, StructureVerifierError};
use crate::il::common::{
    ControlFlowIl, FlagId, IlArtefact, IlBlockArgId, IlError, IlOpId, IlSsaDef, IlValueId,
    RegisterId, SsaVerifier, SsaVerifyError,
};
use crate::il::ecode::{ECodeDomain, ECodeIr, ECodeOp, ECodeOpcode};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum VerifyError {
    #[error("block {block} argument count mismatch: expected {expected}, found {found}")]
    BlockArgCount {
        block: u32,
        expected: usize,
        found: usize,
    },
    #[error("ECode operation has a duplicate memory domain")]
    DuplicateMemoryDomain,
    #[error("ECode edge-argument table count mismatch: expected {expected}, found {found}")]
    EdgeArgTableCount { expected: usize, found: usize },
    #[error(transparent)]
    Il(#[from] IlError),
    #[error("ECode value {value} has an inconsistent domain")]
    InconsistentValueDomain { value: u32 },
    #[error("ECode operation {operation} has invalid block placement")]
    InvalidOpPlacement { operation: u32 },
    #[error(
        "ECode operation {operation} has an invalid operand count: expected {expected}, found {found}"
    )]
    InvalidOperandCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
    #[error(
        "ECode operation {operation} has an invalid result count: expected {expected}, found {found}"
    )]
    InvalidResultCount {
        operation: u32,
        expected: usize,
        found: usize,
    },
    #[error("ECode value has an invalid definition")]
    InvalidValueDef,
    #[error(
        "ECode value {value} does not dominate edge from block {predecessor} to block {successor}"
    )]
    NonDominatingEdgeArg {
        value: u32,
        predecessor: u32,
        successor: u32,
    },
    #[error("ECode value {value} does not dominate use by operation {user}")]
    NonDominatingUse { value: u32, user: u32 },
    #[error(transparent)]
    Structure(StructureError),
    #[error("ECode value-domain count mismatch: expected {expected}, found {found}")]
    ValueDomainCount { expected: usize, found: usize },
}

impl VerifyError {
    const fn inconsistent_value_domain(value: IlValueId) -> Self {
        Self::InconsistentValueDomain {
            value: value.value(),
        }
    }

    const fn invalid_operand_count(operation: IlOpId, expected: usize, found: usize) -> Self {
        Self::InvalidOperandCount {
            operation: operation.value(),
            expected,
            found,
        }
    }

    const fn invalid_result_count(operation: IlOpId, expected: usize, found: usize) -> Self {
        Self::InvalidResultCount {
            operation: operation.value(),
            expected,
            found,
        }
    }

    const fn invalid_value_definition() -> Self {
        Self::InvalidValueDef
    }

    const fn value_domain_count(expected: usize, found: usize) -> Self {
        Self::ValueDomainCount { expected, found }
    }
}

impl StructureVerifierError for VerifyError {
    fn structure(error: StructureError) -> Self {
        Self::Structure(error)
    }
}

impl From<SsaVerifyError> for VerifyError {
    fn from(error: SsaVerifyError) -> Self {
        match error {
            SsaVerifyError::BlockArgCount {
                block,
                expected,
                found,
            } => Self::BlockArgCount {
                block,
                expected,
                found,
            },
            SsaVerifyError::DuplicateMemoryDomain => Self::DuplicateMemoryDomain,
            SsaVerifyError::EdgeArgTableCount { expected, found } => {
                Self::EdgeArgTableCount { expected, found }
            }
            SsaVerifyError::Il(error) => Self::Il(error),
            SsaVerifyError::InvalidOpPlacement { operation } => {
                Self::InvalidOpPlacement { operation }
            }
            SsaVerifyError::InvalidValueDef => Self::InvalidValueDef,
            SsaVerifyError::NonDominatingEdgeArg {
                value,
                predecessor,
                successor,
            } => Self::NonDominatingEdgeArg {
                value,
                predecessor,
                successor,
            },
            SsaVerifyError::NonDominatingUse { value, user } => {
                Self::NonDominatingUse { value, user }
            }
        }
    }
}

pub(crate) fn verify(ir: &ECodeIr) -> Result<(), VerifyError> {
    ECodeVerifier { ir }.verify()
}

struct ECodeVerifier<'a> {
    ir: &'a ECodeIr,
}

impl ECodeVerifier<'_> {
    fn verify(&self) -> Result<(), VerifyError> {
        self.ir.verify_structure::<VerifyError>(
            self.ir.source_spans(),
            Some(self.ir.parent_spans()),
            self.ir.ops().len(),
        )?;
        SsaVerifier::new(self.ir).verify_memory_domains()?;
        self.verify_value_domains()?;
        SsaVerifier::new(self.ir).verify_edge_args()?;

        for (arg_index, arg) in self.ir.block_args().iter().enumerate() {
            let arg_id = IlBlockArgId::try_from_index(arg_index)?;
            self.ir.graph().blocks().get(arg.block().index()).ok_or(
                IlError::range_out_of_bounds(arg.block().index(), self.ir.graph().blocks().len()),
            )?;

            self.ir.values().get(arg.value().index()).ok_or_else(|| {
                IlError::range_out_of_bounds(arg.value().index(), self.ir.values().len())
            })?;

            let value = self.ir.values()[arg.value().index()];

            if value.definition() != IlSsaDef::BlockArg(arg_id) || value.width() != arg.width() {
                return Err(VerifyError::invalid_value_definition());
            }
        }

        for (operation_index, operation) in self.ir.ops().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)?;
            operation.results().verify_bounds(self.ir.values().len())?;
            operation
                .operands()
                .verify_bounds(self.ir.op_operands().len())?;

            for result_index in operation.results().start()..operation.results().end() {
                let value = self.ir.values()[result_index];

                if value.definition() != IlSsaDef::Op(operation_id) {
                    return Err(VerifyError::invalid_value_definition());
                }

                if value.width() != operation.width() {
                    return Err(IlError::width_mismatch(ECodeIr::FORM).into());
                }
            }

            if operation.opcode() == ECodeOpcode::Constant && operation.width() > 64 {
                let bytes = usize::try_from(operation.width().div_ceil(8))
                    .map_err(|_| IlError::integer_overflow("ECode constant width"))?;
                let start = usize::try_from(operation.immediate())
                    .map_err(|_| IlError::integer_overflow("ECode constant offset"))?;
                let end = start.saturating_add(bytes);
                if end > self.ir.constant_storage().len() {
                    return Err(IlError::range_out_of_bounds(
                        end,
                        self.ir.constant_storage().len(),
                    )
                    .into());
                }
            }

            self.verify_domain_write(operation_id, operation)?;

            let uniform_operand_width = operation.opcode().has_uniform_operand_width();
            for operand in operation.operands().checked_slice(self.ir.op_operands())? {
                let value = self.ir.values().get(operand.index()).ok_or_else(|| {
                    IlError::range_out_of_bounds(operand.index(), self.ir.values().len())
                })?;

                if uniform_operand_width && value.width() != operation.width() {
                    return Err(IlError::width_mismatch(ECodeIr::FORM).into());
                }
            }

            if operation.opcode().requires_memory_domain() {
                let Some(address_space) = operation.address_space() else {
                    return Err(IlError::missing_component(ECodeIr::FORM, "memory domain").into());
                };

                if self.ir.memory_domain(address_space).is_none() {
                    return Err(IlError::missing_component(ECodeIr::FORM, "memory domain").into());
                }

                self.verify_memory_op(operation_id, operation)?;
            }
        }

        for (value_index, value) in self.ir.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(value_index)?;

            match value.definition() {
                IlSsaDef::Op(operation) => {
                    let Some(operation) = self.ir.ops().get(operation.index()) else {
                        return Err(VerifyError::invalid_value_definition());
                    };

                    if !operation.results().contains_index(value_id.index()) {
                        return Err(VerifyError::invalid_value_definition());
                    }
                }
                IlSsaDef::BlockArg(arg) => {
                    let Some(arg) = self.ir.block_args().get(arg.index()) else {
                        return Err(VerifyError::invalid_value_definition());
                    };

                    if arg.value() != value_id || arg.width() != value.width() {
                        return Err(VerifyError::invalid_value_definition());
                    }
                }
            }
        }

        SsaVerifier::new(self.ir).verify_uses(|incoming, destination| {
            if self.ir.value_domain(incoming) != self.ir.value_domain(destination) {
                return Err(VerifyError::inconsistent_value_domain(destination));
            }
            Ok(())
        })?;

        Ok(())
    }

    fn verify_value_domains(&self) -> Result<(), VerifyError> {
        if self.ir.value_domains().len() != self.ir.values().len() {
            return Err(VerifyError::value_domain_count(
                self.ir.values().len(),
                self.ir.value_domains().len(),
            ));
        }

        for (index, value) in self.ir.values().iter().enumerate() {
            let value_id = IlValueId::try_from_index(index)?;
            let Some(domain) = self.ir.value_domain(value_id) else {
                continue;
            };
            let consistent = match value.definition() {
                IlSsaDef::BlockArg(_) => {
                    if domain.is_register_or_flag() {
                        value.width() != 0
                    } else {
                        value.width() == 0
                    }
                }
                IlSsaDef::Op(operation) => {
                    let operation = self.ir.ops().get(operation.index());
                    match (domain, operation) {
                        (ECodeDomain::Flag(storage), Some(operation)) => {
                            value.width() != 0
                                && operation.immediate() == storage.value()
                                && matches!(
                                    operation.opcode(),
                                    ECodeOpcode::Undefined | ECodeOpcode::WriteFlag
                                )
                        }
                        (ECodeDomain::Memory(space), Some(operation)) => {
                            value.width() == 0
                                && match operation.opcode() {
                                    ECodeOpcode::Store => operation.address_space() == Some(space),
                                    ECodeOpcode::Undefined => {
                                        operation.immediate() == u64::from(space.value())
                                    }
                                    _ => false,
                                }
                        }
                        (ECodeDomain::Register(storage), Some(operation)) => {
                            value.width() != 0
                                && operation.immediate() == storage.value()
                                && matches!(
                                    operation.opcode(),
                                    ECodeOpcode::Undefined | ECodeOpcode::WriteRegister
                                )
                        }
                        (_, None) => false,
                    }
                }
            };
            if !consistent {
                return Err(VerifyError::inconsistent_value_domain(value_id));
            }
        }

        Ok(())
    }

    fn verify_domain_write(
        &self,
        operation_id: IlOpId,
        operation: &ECodeOp,
    ) -> Result<(), VerifyError> {
        let expected_domain = match operation.opcode() {
            ECodeOpcode::WriteFlag => ECodeDomain::Flag(FlagId::new(operation.immediate())),
            ECodeOpcode::WriteRegister => {
                ECodeDomain::Register(RegisterId::new(operation.immediate()))
            }
            _ => return Ok(()),
        };

        if operation.operands().len() != 1 {
            return Err(VerifyError::invalid_operand_count(
                operation_id,
                1,
                operation.operands().len(),
            ));
        }
        if operation.results().len() != 1 {
            return Err(VerifyError::invalid_result_count(
                operation_id,
                1,
                operation.results().len(),
            ));
        }

        let result = IlValueId::try_from_index(operation.results().start())?;
        if self.ir.value_domain(result) != Some(expected_domain) {
            return Err(VerifyError::inconsistent_value_domain(result));
        }

        Ok(())
    }

    fn verify_memory_op(
        &self,
        operation_id: IlOpId,
        operation: &ECodeOp,
    ) -> Result<(), VerifyError> {
        if self.ir.pointer_operand(operation).is_none() {
            return Err(IlError::missing_component(ECodeIr::FORM, "pointer").into());
        }

        let Some(memory) = self.ir.memory_operand(operation) else {
            return Err(IlError::missing_component(ECodeIr::FORM, "memory domain").into());
        };
        let memory = self.ir.values()[memory.index()];

        if memory.width() != 0 {
            return Err(IlError::width_mismatch(ECodeIr::FORM).into());
        }

        if operation.opcode() == ECodeOpcode::Store {
            if operation.results().len() != 1 {
                return Err(VerifyError::invalid_result_count(
                    operation_id,
                    1,
                    operation.results().len(),
                ));
            }

            let result = self.ir.values()[operation.results().start()];

            if result.width() != 0 {
                return Err(IlError::width_mismatch(ECodeIr::FORM).into());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use fugue_bv::BitVec;

    use super::VerifyError;
    use crate::il::common::verify::StructureError;
    use crate::il::common::{
        FlagId, IlArtefact, IlBlock, IlBlockArgId, IlBlockId, IlBlockProperties, IlEdgeKinds,
        IlError, IlGraph, IlGraphBuilder, IlIndexRange, IlMetadata, IlOpId, IlSsaDef, IlValueId,
        RegisterId,
    };
    use crate::il::ecode::ir::ECodeIrStorage;
    use crate::il::ecode::optimise::ECodeConstantFolding;
    use crate::il::ecode::{
        ECodeBlockArg, ECodeBuilder, ECodeDomain, ECodeIr, ECodeMemoryDomain, ECodeOp, ECodeOpSpec,
        ECodeOpcode, ECodeValue,
    };
    use crate::ir::FunctionId;
    use crate::storage::segments::space::AddressSpaceId;

    fn emit_value(
        builder: &mut ECodeBuilder,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let (_, results) = builder.emitter().emit(spec, operands, 1)?;
        IlValueId::try_from_index(results.start())
    }

    #[derive(Default)]
    struct ECodeFixture {
        values: Vec<ECodeValue>,
        block_args: Vec<ECodeBlockArg>,
        edge_args: Vec<IlIndexRange>,
        edge_arg_values: Vec<IlValueId>,
        operations: Vec<ECodeOp>,
        value_operands: Vec<IlValueId>,
        memory_domains: Vec<ECodeMemoryDomain>,
        constant_storage: Vec<u8>,
    }

    impl ECodeFixture {
        fn with_values(mut self, values: Vec<ECodeValue>, block_args: Vec<ECodeBlockArg>) -> Self {
            self.values = values;
            self.block_args = block_args;
            self
        }

        fn with_operations(
            mut self,
            operations: Vec<ECodeOp>,
            value_operands: Vec<IlValueId>,
        ) -> Self {
            self.operations = operations;
            self.value_operands = value_operands;
            self
        }

        fn with_edge_arg_storage(
            mut self,
            edge_args: Vec<IlIndexRange>,
            edge_arg_values: Vec<IlValueId>,
        ) -> Self {
            self.edge_args = edge_args;
            self.edge_arg_values = edge_arg_values;
            self
        }

        fn with_memory_domains(mut self, memory_domains: Vec<ECodeMemoryDomain>) -> Self {
            self.memory_domains = memory_domains;
            self
        }

        fn with_constant_storage(mut self, constant_storage: Vec<u8>) -> Self {
            self.constant_storage = constant_storage;
            self
        }

        fn build(self, metadata: IlMetadata, graph: IlGraph) -> ECodeIr {
            let value_domains = vec![None; self.values.len()];
            ECodeIr::new(ECodeIrStorage {
                metadata,
                graph,
                source_spans: Vec::new(),
                parent_spans: Vec::new(),
                values: self.values,
                value_domains,
                block_args: self.block_args,
                edge_args: self.edge_args,
                edge_arg_values: self.edge_arg_values,
                operations: self.operations,
                value_operands: self.value_operands,
                memory_domains: self.memory_domains,
                constant_storage: self.constant_storage,
            })
        }
    }

    #[test]
    fn ecode_verifier_rejects_invalid_value_definition() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let ir = ECodeFixture::default()
            .with_values(
                vec![ECodeValue::new(
                    64,
                    IlSsaDef::Op(IlOpId::try_from_index(3).unwrap()),
                )],
                Vec::new(),
            )
            .build(metadata, IlGraph::default());

        assert!(matches!(ir.verify(), Err(VerifyError::InvalidValueDef)));
    }

    #[test]
    fn ecode_verifier_rejects_register_write_with_wrong_domain() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let source = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();

        let (_, written_results) = builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::WriteRegister, 64).with_immediate(7),
                [source],
                1,
            )
            .unwrap();
        let written = IlValueId::try_from_index(written_results.start()).unwrap();
        builder
            .emitter()
            .set_value_domain(written, ECodeDomain::Flag(FlagId::new(7)))
            .unwrap();

        let ir = builder.build_unchecked();

        assert_eq!(
            ir.verify(),
            Err(VerifyError::InconsistentValueDomain {
                value: written.value(),
            })
        );
    }

    #[test]
    fn ecode_verifier_rejects_duplicate_memory_domains() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let space = AddressSpaceId::new(7);
        let ir = ECodeFixture::default()
            .with_memory_domains(vec![
                ECodeMemoryDomain::new(space),
                ECodeMemoryDomain::new(space),
            ])
            .build(metadata, IlGraph::default());

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::DuplicateMemoryDomain)
        ));
    }

    #[test]
    fn ecode_verifier_rejects_load_without_memory_domain() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let space = AddressSpaceId::new(7);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Load, 8).with_address_space(space),
                [],
                1,
            )
            .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::MissingComponent { .. }))
        ));
    }

    #[test]
    fn ecode_verifier_indexes_block_args_in_a_large_chain() {
        const BLOCK_COUNT: usize = 512;

        let mut graph = IlGraphBuilder::new();
        let mut blocks = Vec::with_capacity(BLOCK_COUNT);
        blocks.push(
            graph
                .push_block(IlIndexRange::new(0, 1).unwrap(), IlBlockProperties::ENTRY)
                .unwrap(),
        );
        for _ in 1..BLOCK_COUNT {
            blocks.push(
                graph
                    .push_block(IlIndexRange::new(1, 1).unwrap(), IlBlockProperties::empty())
                    .unwrap(),
            );
        }
        for pair in blocks.windows(2) {
            graph
                .add_successor(pair[0], pair[1], IlEdgeKinds::FALL_THROUGH)
                .unwrap();
        }

        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, graph.build(1).unwrap());
        let mut incoming = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();
        for &block in &blocks[1..] {
            let arg = builder.emitter().emit_block_arg(block, 64).unwrap();
            builder.emitter().emit_edge_args([incoming]).unwrap();
            incoming = arg;
        }

        let ir = builder.build_unchecked();

        assert_eq!(ir.verify(), Ok(()));
    }

    #[test]
    fn ecode_verifier_reports_invalid_store_result_count() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let space = AddressSpaceId::new(7);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        builder.emitter().intern_memory_domain(space);

        let pointer = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();

        let value =
            emit_value(&mut builder, ECodeOpSpec::new(ECodeOpcode::Constant, 8), []).unwrap();

        let memory = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 0),
            [],
        )
        .unwrap();

        builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Store, 0).with_address_space(space),
                [pointer, value, memory],
                0,
            )
            .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::InvalidResultCount {
                operation: 4,
                expected: 1,
                found: 0,
            })
        ));
    }

    #[test]
    fn ecode_verifier_rejects_wide_constant_beyond_pool() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let _value = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 128).with_immediate(100),
            [],
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn ecode_verifier_rejects_operand_width_mismatch() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());

        let wide = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();

        emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Add, 32),
            [wide, wide],
        )
        .unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::WidthMismatch { .. }))
        ));
    }

    #[test]
    fn ecode_verifier_accepts_wide_constant_within_pool() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());

        let source = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(0xabc),
            [],
        )
        .unwrap();

        let widened = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::ZeroExtend, 128),
            [source],
        )
        .unwrap();

        builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [widened], 0)
            .unwrap();

        let mut ir = builder.build_unchecked();
        ir.verify().unwrap();

        ir.rewrite(ECodeConstantFolding);

        ir.verify().unwrap();
        assert_eq!(
            ir.constant_value(widened),
            Some(BitVec::from_u64(0xabc, 64).unsigned_cast(128))
        );
    }

    #[test]
    fn ecode_verifier_bounds_wide_constant_at_pool_edge() {
        let wide_constant = |pool_len: usize| {
            let metadata = IlMetadata::new(FunctionId::default(), 0);
            ECodeFixture::default()
                .with_values(
                    vec![ECodeValue::op_result(
                        128,
                        IlOpId::try_from_index(0).unwrap(),
                    )],
                    Vec::new(),
                )
                .with_operations(
                    vec![
                        ECodeOp::new(
                            ECodeOpcode::Constant,
                            IlIndexRange::new(0, 1).unwrap(),
                            IlIndexRange::EMPTY,
                            128,
                        )
                        .with_immediate(0),
                    ],
                    Vec::new(),
                )
                .with_constant_storage(vec![0u8; pool_len])
                .build(metadata, IlGraph::default())
        };

        wide_constant(16).verify().unwrap();

        assert!(matches!(
            wide_constant(15).verify(),
            Err(VerifyError::Il(IlError::RangeOutOfBounds { .. }))
        ));
    }

    #[test]
    fn ecode_verifier_rejects_non_dominating_linear_use() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let value = IlValueId::try_from_index(0).unwrap();
        let result = IlIndexRange::new(0, 1).unwrap();
        let operands = IlIndexRange::new(0, 1).unwrap();
        let ir = ECodeFixture::default()
            .with_values(
                vec![ECodeValue::op_result(
                    32,
                    IlOpId::try_from_index(1).unwrap(),
                )],
                Vec::new(),
            )
            .with_operations(
                vec![
                    ECodeOp::new(ECodeOpcode::Return, IlIndexRange::EMPTY, operands, 0),
                    ECodeOp::new(ECodeOpcode::Constant, result, IlIndexRange::EMPTY, 32),
                ],
                vec![value],
            )
            .build(metadata, IlGraph::default());

        let result = ir.verify();
        assert!(
            matches!(result, Err(VerifyError::NonDominatingUse { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn ecode_verifier_rejects_non_dominating_block_use() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let left = IlBlockId::try_from_index(1).unwrap();
        let right = IlBlockId::try_from_index(2).unwrap();
        let value = IlValueId::try_from_index(0).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 2).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 2).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
            ],
            vec![left, right],
            vec![IlEdgeKinds::UNCONDITIONAL; 2],
        );
        let ir = ECodeFixture::default()
            .with_values(
                vec![ECodeValue::op_result(
                    32,
                    IlOpId::try_from_index(0).unwrap(),
                )],
                Vec::new(),
            )
            .with_operations(
                vec![
                    ECodeOp::new(
                        ECodeOpcode::Constant,
                        IlIndexRange::new(0, 1).unwrap(),
                        IlIndexRange::EMPTY,
                        32,
                    ),
                    ECodeOp::new(
                        ECodeOpcode::Return,
                        IlIndexRange::EMPTY,
                        IlIndexRange::new(0, 1).unwrap(),
                        0,
                    ),
                ],
                vec![value],
            )
            .with_edge_arg_storage(vec![IlIndexRange::EMPTY; 2], Vec::new())
            .build(metadata, graph);

        let result = ir.verify();
        assert!(
            matches!(result, Err(VerifyError::NonDominatingUse { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn ecode_verifier_rejects_wrong_edge_arg_table_count() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let successor = IlBlockId::try_from_index(1).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![successor],
            vec![IlEdgeKinds::UNCONDITIONAL],
        );
        let ir = ECodeFixture::default().build(metadata, graph);

        assert_eq!(
            ir.verify(),
            Err(VerifyError::EdgeArgTableCount {
                expected: 1,
                found: 0,
            })
        );
    }

    #[test]
    fn ecode_verifier_rejects_wrong_edge_arg_count() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let successor = IlBlockId::try_from_index(1).unwrap();
        let arg_value = IlValueId::try_from_index(0).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![successor],
            vec![IlEdgeKinds::UNCONDITIONAL; 1],
        );
        let ir = ECodeFixture::default()
            .with_values(
                vec![ECodeValue::block_arg(
                    32,
                    IlBlockArgId::try_from_index(0).unwrap(),
                )],
                vec![ECodeBlockArg::new(successor, arg_value, 32)],
            )
            .with_edge_arg_storage(vec![IlIndexRange::EMPTY], Vec::new())
            .build(metadata, graph);

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::BlockArgCount { .. })
        ));
    }

    #[test]
    fn ecode_verifier_rejects_non_dominating_edge_arg() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let left = IlBlockId::try_from_index(1).unwrap();
        let right = IlBlockId::try_from_index(2).unwrap();
        let value = IlValueId::try_from_index(0).unwrap();
        let arg_value = IlValueId::try_from_index(1).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 2).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![left, right],
            vec![IlEdgeKinds::UNCONDITIONAL; 2],
        );
        let ir = ECodeFixture::default()
            .with_values(
                vec![
                    ECodeValue::op_result(32, IlOpId::try_from_index(0).unwrap()),
                    ECodeValue::block_arg(32, IlBlockArgId::try_from_index(0).unwrap()),
                ],
                vec![ECodeBlockArg::new(right, arg_value, 32)],
            )
            .with_operations(
                vec![ECodeOp::new(
                    ECodeOpcode::Constant,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    32,
                )],
                Vec::new(),
            )
            .with_edge_arg_storage(
                vec![IlIndexRange::EMPTY, IlIndexRange::new(0, 1).unwrap()],
                vec![value],
            )
            .build(metadata, graph);

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::NonDominatingEdgeArg { .. })
        ));
    }

    #[test]
    fn ecode_verifier_rejects_duplicate_operation_placement() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
            ],
            Vec::new(),
            Vec::new(),
        );
        let ir = ECodeFixture::default()
            .with_values(
                vec![ECodeValue::op_result(
                    32,
                    IlOpId::try_from_index(0).unwrap(),
                )],
                Vec::new(),
            )
            .with_operations(
                vec![ECodeOp::new(
                    ECodeOpcode::Constant,
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    32,
                )],
                Vec::new(),
            )
            .build(metadata, graph);

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Structure(
                StructureError::OverlappingBlockOps { .. }
            ))
        ));
    }

    #[test]
    fn ecode_verifier_rejects_an_edge_arg_from_a_different_domain() {
        let successor = IlBlockId::try_from_index(1).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 2).unwrap(),
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![successor],
            vec![IlEdgeKinds::UNCONDITIONAL],
        );
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0), graph);

        let left = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 64).with_immediate(16),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .set_value_domain(left, ECodeDomain::Register(RegisterId::new(16)))
            .unwrap();
        let right = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 64).with_immediate(24),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .set_value_domain(right, ECodeDomain::Register(RegisterId::new(24)))
            .unwrap();

        let arg = builder.emitter().emit_block_arg(successor, 64).unwrap();
        builder
            .emitter()
            .set_value_domain(arg, ECodeDomain::Register(RegisterId::new(24)))
            .unwrap();
        builder.emitter().emit_edge_args([left]).unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::InconsistentValueDomain { .. })
        ));
    }

    #[test]
    fn ecode_verifier_checks_edge_arg_width_from_an_unreachable_block() {
        let successor = IlBlockId::try_from_index(2).unwrap();
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![successor],
            vec![IlEdgeKinds::UNCONDITIONAL],
        );
        let mut builder = ECodeBuilder::new(IlMetadata::new(FunctionId::default(), 0), graph);
        let incoming = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 32),
            [],
        )
        .unwrap();
        builder.emitter().emit_block_arg(successor, 64).unwrap();
        builder.emitter().emit_edge_args([incoming]).unwrap();

        let ir = builder.build_unchecked();

        assert!(matches!(
            ir.verify(),
            Err(VerifyError::Il(IlError::WidthMismatch { .. }))
        ));
    }
}
