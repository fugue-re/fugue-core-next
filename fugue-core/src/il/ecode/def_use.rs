use crate::il::common::{
    IlAnalysis, IlCsr, IlOpId, IlSsaBlockArgInputs, IlValueId,
    collect_ssa_uses,
};
use crate::il::ecode::ECodeIr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct ECodeUse {
    user: IlOpId,
    operand_index: u32,
}

impl ECodeUse {
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
pub struct ECodeUses {
    uses: IlCsr<ECodeUse>,
}

impl ECodeUses {
    pub fn uses_for(&self, value: IlValueId) -> &[ECodeUse] {
        self.uses.checked_row(value.index()).unwrap_or_default()
    }
}

impl IlAnalysis<ECodeIr> for ECodeUses {
    fn analyse(ir: &ECodeIr) -> Self {
        Self {
            uses: collect_ssa_uses(
                ir.values().len(),
                ir.operations()
                    .iter()
                    .map(|operation| ir.operation_operands_for(operation)),
                ECodeUse::new,
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ECodeBlockArgInputs {
    inputs: IlSsaBlockArgInputs,
}

impl ECodeBlockArgInputs {
    pub fn inputs_for(&self, arg: IlValueId) -> Option<&[IlValueId]> {
        self.inputs.inputs_for(arg)
    }

    pub(crate) fn iter(&self) -> impl Clone + Iterator<Item = (IlValueId, &[IlValueId])> {
        self.inputs.iter()
    }
}

impl IlAnalysis<ECodeIr> for ECodeBlockArgInputs {
    fn analyse(ir: &ECodeIr) -> Self {
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
    use crate::il::ecode::test::emit_value;
    use crate::il::ecode::{ECodeBuilder, ECodeOpSpec, ECodeOpcode};
    use crate::ir::FunctionId;

    #[test]
    fn uses_builds_from_ecode_body() {
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let left = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();
        let right = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();
        let (user, _) = builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Add, 64),
                [left, right, left],
                0,
            )
            .unwrap();
        let ir = builder.build(&CancellationToken::default()).unwrap();
        let index = ir.analyse::<ECodeUses>();

        assert_eq!(
            index.uses_for(left),
            &[ECodeUse::new(user, 0), ECodeUse::new(user, 2)]
        );
        assert_eq!(index.uses_for(right), &[ECodeUse::new(user, 1)]);
    }
}
