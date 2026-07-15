use crate::il::common::{IlError, OperationId, ValueId};
use crate::il::llil::ssa::SsaBody;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct Use {
    user: OperationId,
    operand_index: u32,
}

impl Use {
    pub const fn new(user: OperationId, operand_index: u32) -> Self {
        Self {
            user,
            operand_index,
        }
    }

    pub const fn user(&self) -> OperationId {
        self.user
    }

    pub const fn operand_index(&self) -> u32 {
        self.operand_index
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UseIndex {
    offsets: Vec<u32>,
    uses: Vec<Use>,
}

impl UseIndex {
    pub fn new(offsets: Vec<u32>, uses: Vec<Use>) -> Self {
        Self { offsets, uses }
    }

    pub fn build(body: &SsaBody) -> Result<Self, IlError> {
        let mut offsets = vec![0u32; body.values().len() + 1];

        for operation in body.operations() {
            for operand in operation.operands().checked_slice(body.value_operands())? {
                let index = operand.index() + 1;
                offsets[index] = offsets[index]
                    .checked_add(1)
                    .ok_or(IlError::integer_overflow("SSA use count"))?;
            }
        }

        for index in 1..offsets.len() {
            offsets[index] = offsets[index]
                .checked_add(offsets[index - 1])
                .ok_or(IlError::integer_overflow("SSA use offset"))?;
        }

        let mut cursor = offsets.clone();
        let mut uses = vec![
            Use::new(OperationId::try_from_index(0)?, 0);
            *offsets.last().unwrap_or(&0) as usize
        ];

        for (operation_index, operation) in body.operations().iter().enumerate() {
            let operation_id = OperationId::try_from_index(operation_index)?;

            for (operand_index, operand) in operation
                .operands()
                .checked_slice(body.value_operands())?
                .iter()
                .enumerate()
            {
                let cursor_index = operand.index();
                let use_index = cursor[cursor_index] as usize;
                let operand_index = u32::try_from(operand_index)
                    .map_err(|_| IlError::integer_overflow("SSA operand index"))?;

                uses[use_index] = Use::new(operation_id, operand_index);
                cursor[cursor_index] += 1;
            }
        }

        Ok(Self { offsets, uses })
    }

    pub fn uses_for(&self, value: ValueId) -> &[Use] {
        let index = value.index();
        let Some(start) = self.offsets.get(index).copied() else {
            return &[];
        };
        let end = self.offsets.get(index + 1).copied().unwrap_or(start);

        &self.uses[start as usize..end as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{
        ArtefactHeader, BuildStatus, CommonBody, Finish, IrLevel, PackedRange,
    };
    use crate::il::llil::ssa::{LLIL_SSA_SCHEMA_VERSION, SsaBuilder, SsaOpcode, SsaOperation};
    use crate::ir::FunctionId;

    #[test]
    fn use_index_returns_value_uses() {
        let value = ValueId::try_from_index(0).unwrap();
        let user = OperationId::try_from_index(2).unwrap();
        let index = UseIndex::new(vec![0, 1], vec![Use::new(user, 3)]);

        assert_eq!(index.uses_for(value), &[Use::new(user, 3)]);
    }

    #[test]
    fn use_index_builds_from_ssa_body() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let mut builder = SsaBuilder::new(header, CommonBody::default());
        let (left, left_results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Constant,
                left_results,
                PackedRange::EMPTY,
                64,
            ))
            .unwrap();

        let (right, right_results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Constant,
                right_results,
                PackedRange::EMPTY,
                64,
            ))
            .unwrap();

        let operands = builder.push_value_operands([left, right, left]).unwrap();
        let user = builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Add,
                PackedRange::EMPTY,
                operands,
                64,
            ))
            .unwrap();
        let body = builder.finish(&BuildStatus::new()).unwrap();
        let index = UseIndex::build(&body).unwrap();

        assert_eq!(
            index.uses_for(left),
            &[Use::new(user, 0), Use::new(user, 2)]
        );
        assert_eq!(index.uses_for(right), &[Use::new(user, 1)]);
    }
}
