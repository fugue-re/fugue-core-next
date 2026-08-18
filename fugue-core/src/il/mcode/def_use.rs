use crate::il::common::{
    IlAnalysis, IlCsr, IlOpId, IlSsaBlockArgInputs, IlValueId,
    collect_ssa_uses,
};
use crate::il::mcode::MCodeIr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct MCodeUse {
    user: IlOpId,
    operand_index: u32,
}

impl MCodeUse {
    const fn new(user: IlOpId, operand_index: usize) -> Self {
        Self {
            user,
            operand_index: operand_index as u32,
        }
    }

    pub const fn user(&self) -> IlOpId {
        self.user
    }

    pub const fn operand_index(&self) -> usize {
        self.operand_index as usize
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MCodeUses {
    uses: IlCsr<MCodeUse>,
}

impl MCodeUses {
    pub fn uses_for(&self, value: IlValueId) -> &[MCodeUse] {
        self.uses.checked_row(value.index()).unwrap_or_default()
    }
}

impl IlAnalysis<MCodeIr> for MCodeUses {
    fn analyse(ir: &MCodeIr) -> Self {
        Self {
            uses: collect_ssa_uses(
                ir.values().len(),
                ir.ops()
                    .iter()
                    .map(|operation| ir.op_operands_for(operation)),
                MCodeUse::new,
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MCodeBlockArgInputs {
    inputs: IlSsaBlockArgInputs,
}

impl MCodeBlockArgInputs {
    pub fn inputs_for(&self, arg: IlValueId) -> Option<&[IlValueId]> {
        self.inputs.inputs_for(arg)
    }

    pub(crate) fn iter(&self) -> impl Clone + Iterator<Item = (IlValueId, &[IlValueId])> {
        self.inputs.iter()
    }
}

impl IlAnalysis<MCodeIr> for MCodeBlockArgInputs {
    fn analyse(ir: &MCodeIr) -> Self {
        Self {
            inputs: IlSsaBlockArgInputs::new(
                ir.values().len(),
                ir.graph(),
                ir.block_args().iter().map(|arg| (arg.block(), arg.value())),
                |edge| ir.args_for_edge(edge),
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlArtefact, IlGraph, IlMetadata};
    use crate::il::mcode::test::emit_value;
    use crate::il::mcode::{MCodeBuilder, MCodeOpSpec, MCodeOpcode};
    use crate::ir::FunctionId;

    #[test]
    fn uses_preserve_operand_positions() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = MCodeBuilder::new(metadata, IlGraph::default());
        let left = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 64),
            [],
            64,
        )
        .unwrap();
        let right = emit_value(
            &mut builder,
            MCodeOpSpec::new(MCodeOpcode::Constant, 64),
            [],
            64,
        )
        .unwrap();
        let (user, _) = builder
            .emitter()
            .emit(
                MCodeOpSpec::new(MCodeOpcode::Intrinsic, 0),
                [left, right, left],
                [],
            )
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();
        let uses = ir.analyse::<MCodeUses>();

        assert_eq!(
            uses.uses_for(left),
            &[MCodeUse::new(user, 0), MCodeUse::new(user, 2)]
        );
        assert_eq!(uses.uses_for(right), &[MCodeUse::new(user, 1)]);
    }
}
