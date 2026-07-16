use crate::il::common::{IlOpId, IlValueId};
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
    offsets: Vec<u32>,
    uses: Vec<ECodeSsaUse>,
}

impl ECodeSsaUses {
    pub fn build(body: &ECodeSsaIr) -> Self {
        let mut offsets = vec![0u32; body.values().len() + 1];

        for operation in body.operations() {
            for operand in operation.operands().slice(body.value_operands()) {
                offsets[operand.index() + 1] += 1;
            }
        }

        for index in 1..offsets.len() {
            offsets[index] += offsets[index - 1];
        }

        let mut cursor = offsets.clone();
        let fill = IlOpId::try_from_index(0).expect("operation id zero is representable");
        let mut uses = vec![ECodeSsaUse::new(fill, 0); *offsets.last().unwrap_or(&0) as usize];

        for (operation_index, operation) in body.operations().iter().enumerate() {
            let operation_id = IlOpId::try_from_index(operation_index)
                .expect("operation count fits the operation id space");

            for (operand_index, operand) in operation
                .operands()
                .slice(body.value_operands())
                .iter()
                .enumerate()
            {
                let cursor_index = operand.index();
                let slot = cursor[cursor_index] as usize;

                uses[slot] = ECodeSsaUse::new(operation_id, operand_index as u32);
                cursor[cursor_index] += 1;
            }
        }

        Self { offsets, uses }
    }

    pub fn uses_for(&self, value: IlValueId) -> &[ECodeSsaUse] {
        let index = value.index();
        let Some(start) = self.offsets.get(index).copied() else {
            return &[];
        };
        let end = self.offsets.get(index + 1).copied().unwrap_or(start);

        &self.uses[start as usize..end as usize]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlGraph, IlHeader, IlIndexRange};
    use crate::il::ecode::ssa::{
        ECODE_SSA_SCHEMA_VERSION, ECodeSsaBuilder, ECodeSsaOp, ECodeSsaOpcode,
    };
    use crate::ir::FunctionId;

    #[test]
    fn uses_returns_value_uses() {
        let value = IlValueId::try_from_index(0).unwrap();
        let user = IlOpId::try_from_index(2).unwrap();
        let index = ECodeSsaUses {
            offsets: vec![0, 1],
            uses: vec![ECodeSsaUse::new(user, 3)],
        };

        assert_eq!(index.uses_for(value), &[ECodeSsaUse::new(user, 3)]);
    }

    #[test]
    fn uses_builds_from_ssa_body() {
        let header = IlHeader::new(FunctionId::default(), ECODE_SSA_SCHEMA_VERSION, 0);
        let mut builder = ECodeSsaBuilder::new(header, IlGraph::default());
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
        let body = builder.build(&CancellationToken::default()).unwrap();
        let index = ECodeSsaUses::build(&body);

        assert_eq!(
            index.uses_for(left),
            &[ECodeSsaUse::new(user, 0), ECodeSsaUse::new(user, 2)]
        );
        assert_eq!(index.uses_for(right), &[ECodeSsaUse::new(user, 1)]);
    }
}
