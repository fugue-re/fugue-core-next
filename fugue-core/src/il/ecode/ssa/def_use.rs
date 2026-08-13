use rustc_hash::FxHashMap;

use crate::il::common::{
    IlAnalysis, IlCsr, IlOpId, IlValueId, build_ssa_block_argument_inputs, build_ssa_uses,
};
use crate::il::ecode::ssa::ECodeSsaIr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct ECodeSsaUse {
    user: IlOpId,
    operand_index: u32,
}

impl ECodeSsaUse {
    pub(crate) const fn new(user: IlOpId, operand_index: u32) -> Self {
        Self {
            user,
            operand_index,
        }
    }

    pub const fn user(&self) -> IlOpId {
        self.user
    }

    pub const fn operand_index(&self) -> u32 {
        self.operand_index
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ECodeSsaUses {
    uses: IlCsr<ECodeSsaUse>,
}

impl ECodeSsaUses {
    pub fn uses_for(&self, value: IlValueId) -> &[ECodeSsaUse] {
        self.uses.row(value.index())
    }
}

impl IlAnalysis<ECodeSsaIr> for ECodeSsaUses {
    fn analyse(ir: &ECodeSsaIr) -> Self {
        Self {
            uses: build_ssa_uses(
                ir.values().len(),
                ir.operations()
                    .iter()
                    .map(|operation| ir.operation_operands_for(operation)),
                ECodeSsaUse::new,
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ECodeSsaBlockArgInputs {
    inputs: FxHashMap<IlValueId, Vec<IlValueId>>,
}

impl ECodeSsaBlockArgInputs {
    pub fn inputs_for(&self, argument: IlValueId) -> Option<&[IlValueId]> {
        self.inputs.get(&argument).map(Vec::as_slice)
    }

    pub(crate) fn iter(&self) -> impl Clone + Iterator<Item = (IlValueId, &[IlValueId])> {
        self.inputs
            .iter()
            .map(|(&argument, inputs)| (argument, inputs.as_slice()))
    }
}

impl IlAnalysis<ECodeSsaIr> for ECodeSsaBlockArgInputs {
    fn analyse(ir: &ECodeSsaIr) -> Self {
        Self {
            inputs: build_ssa_block_argument_inputs(
                ir.graph(),
                ir.block_arguments()
                    .iter()
                    .map(|argument| (argument.block(), argument.value())),
                |edge| ir.arguments_for_edge(edge),
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlArtefact, IlGraph, IlIndexRange, IlMetadata};
    use crate::il::ecode::ssa::{ECodeSsaBuilder, ECodeSsaOp, ECodeSsaOpcode};
    use crate::ir::FunctionId;

    #[test]
    fn uses_builds_from_ssa_body() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());
        let (left, left_results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                left_results,
                IlIndexRange::EMPTY,
                64,
            ))
            .unwrap();

        let (right, right_results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Constant,
                right_results,
                IlIndexRange::EMPTY,
                64,
            ))
            .unwrap();

        let operands = builder.push_value_operands([left, right, left]).unwrap();
        let user = builder
            .push_operation(ECodeSsaOp::new(
                ECodeSsaOpcode::Add,
                IlIndexRange::EMPTY,
                operands,
                64,
            ))
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();
        let index = ir.analyse::<ECodeSsaUses>();

        assert_eq!(
            index.uses_for(left),
            &[ECodeSsaUse::new(user, 0), ECodeSsaUse::new(user, 2)]
        );
        assert_eq!(index.uses_for(right), &[ECodeSsaUse::new(user, 1)]);
    }
}
