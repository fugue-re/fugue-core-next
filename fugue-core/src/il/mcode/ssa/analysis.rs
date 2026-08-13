use rustc_hash::FxHashMap;

use crate::il::common::{
    IlAnalysis, IlCsr, IlOpId, IlValueId, build_ssa_block_argument_inputs, build_ssa_uses,
};
use crate::il::mcode::ssa::MCodeSsaIr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct MCodeSsaUse {
    user: IlOpId,
    operand_index: u32,
}

impl MCodeSsaUse {
    const fn new(user: IlOpId, operand_index: u32) -> Self {
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
pub struct MCodeSsaUses {
    uses: IlCsr<MCodeSsaUse>,
}

impl MCodeSsaUses {
    pub fn uses_for(&self, value: IlValueId) -> &[MCodeSsaUse] {
        self.uses.row(value.index())
    }
}

impl IlAnalysis<MCodeSsaIr> for MCodeSsaUses {
    fn analyse(ir: &MCodeSsaIr) -> Self {
        Self {
            uses: build_ssa_uses(
                ir.values().len(),
                ir.operations()
                    .iter()
                    .map(|operation| ir.operation_operands_for(operation)),
                MCodeSsaUse::new,
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MCodeSsaBlockArgInputs {
    inputs: FxHashMap<IlValueId, Vec<IlValueId>>,
}

impl MCodeSsaBlockArgInputs {
    pub fn inputs_for(&self, argument: IlValueId) -> Option<&[IlValueId]> {
        self.inputs.get(&argument).map(Vec::as_slice)
    }

    pub(crate) fn iter(&self) -> impl Clone + Iterator<Item = (IlValueId, &[IlValueId])> {
        self.inputs
            .iter()
            .map(|(&argument, inputs)| (argument, inputs.as_slice()))
    }
}

impl IlAnalysis<MCodeSsaIr> for MCodeSsaBlockArgInputs {
    fn analyse(ir: &MCodeSsaIr) -> Self {
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
    use crate::il::mcode::ssa::{MCodeSsaBuilder, MCodeSsaOp, MCodeSsaOpcode};
    use crate::ir::FunctionId;

    #[test]
    fn uses_preserve_operand_positions() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = MCodeSsaBuilder::new(metadata, IlGraph::default());
        let left_results = builder.push_result_values([64]).unwrap();
        let left = IlValueId::try_from_index(left_results.start()).unwrap();
        builder
            .push_operation(MCodeSsaOp::new(
                MCodeSsaOpcode::Constant,
                left_results,
                IlIndexRange::EMPTY,
                64,
            ))
            .unwrap();

        let right_results = builder.push_result_values([64]).unwrap();
        let right = IlValueId::try_from_index(right_results.start()).unwrap();
        builder
            .push_operation(MCodeSsaOp::new(
                MCodeSsaOpcode::Constant,
                right_results,
                IlIndexRange::EMPTY,
                64,
            ))
            .unwrap();

        let operands = builder.push_value_operands([left, right, left]).unwrap();
        let user = builder
            .push_operation(MCodeSsaOp::new(
                MCodeSsaOpcode::Intrinsic,
                IlIndexRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();
        let uses = ir.analyse::<MCodeSsaUses>();

        assert_eq!(
            uses.uses_for(left),
            &[MCodeSsaUse::new(user, 0), MCodeSsaUse::new(user, 2)]
        );
        assert_eq!(uses.uses_for(right), &[MCodeSsaUse::new(user, 1)]);
    }
}
