use crate::il::common::{BlockId, IlError, ValueId};
use crate::il::llil::ssa::SsaBody;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Liveness {
    live_in_offsets: Vec<u32>,
    live_in_values: Vec<ValueId>,
    live_out_offsets: Vec<u32>,
    live_out_values: Vec<ValueId>,
}

impl Liveness {
    pub fn new(
        live_in_offsets: Vec<u32>,
        live_in_values: Vec<ValueId>,
        live_out_offsets: Vec<u32>,
        live_out_values: Vec<ValueId>,
    ) -> Self {
        Self {
            live_in_offsets,
            live_in_values,
            live_out_offsets,
            live_out_values,
        }
    }

    pub fn build(body: &SsaBody) -> Result<Self, IlError> {
        let block_count = body.common().blocks().len();
        let value_count = body.values().len();

        if block_count == 0 {
            return Ok(Self::default());
        }

        let mut block_use = vec![vec![false; value_count]; block_count];
        let mut block_def = vec![vec![false; value_count]; block_count];

        Self::collect_block_arguments(body, &mut block_def)?;
        Self::collect_operation_uses(body, &mut block_use, &mut block_def)?;

        let mut live_in = vec![vec![false; value_count]; block_count];
        let mut live_out = vec![vec![false; value_count]; block_count];
        let mut changed = true;

        while changed {
            changed = false;

            for (block_index, block) in body.common().blocks().iter().enumerate().rev() {
                let mut next_live_out = vec![false; value_count];

                for successor in block
                    .successors()
                    .checked_slice(body.common().successors())?
                {
                    let successor_live_in = live_in
                        .get(successor.index())
                        .ok_or(IlError::range_out_of_bounds(successor.value(), block_count))?;

                    for (value_index, live) in successor_live_in.iter().enumerate() {
                        next_live_out[value_index] |= *live;
                    }
                }

                let mut next_live_in = block_use[block_index].clone();

                for value_index in 0..value_count {
                    next_live_in[value_index] |=
                        next_live_out[value_index] && !block_def[block_index][value_index];
                }

                if live_out[block_index] != next_live_out {
                    live_out[block_index] = next_live_out;
                    changed = true;
                }

                if live_in[block_index] != next_live_in {
                    live_in[block_index] = next_live_in;
                    changed = true;
                }
            }
        }

        let (live_in_offsets, live_in_values) = Self::pack_sets(&live_in)?;
        let (live_out_offsets, live_out_values) = Self::pack_sets(&live_out)?;

        Ok(Self {
            live_in_offsets,
            live_in_values,
            live_out_offsets,
            live_out_values,
        })
    }

    pub fn live_in(&self, block: BlockId) -> &[ValueId] {
        Self::values_for(block, &self.live_in_offsets, &self.live_in_values)
    }

    pub fn live_out(&self, block: BlockId) -> &[ValueId] {
        Self::values_for(block, &self.live_out_offsets, &self.live_out_values)
    }

    fn collect_block_arguments(body: &SsaBody, block_def: &mut [Vec<bool>]) -> Result<(), IlError> {
        for argument in body.block_arguments() {
            let block =
                block_def
                    .get_mut(argument.block().index())
                    .ok_or(IlError::range_out_of_bounds(
                        argument.block().value(),
                        body.common().blocks().len(),
                    ))?;
            let value =
                block
                    .get_mut(argument.value().index())
                    .ok_or(IlError::range_out_of_bounds(
                        argument.value().value(),
                        body.values().len(),
                    ))?;

            *value = true;
        }

        Ok(())
    }

    fn collect_operation_uses(
        body: &SsaBody,
        block_use: &mut [Vec<bool>],
        block_def: &mut [Vec<bool>],
    ) -> Result<(), IlError> {
        for (block_index, block) in body.common().blocks().iter().enumerate() {
            for operation in block.operations().checked_slice(body.operations())? {
                for operand in operation.operands().checked_slice(body.value_operands())? {
                    let value_index = operand.index();

                    if body.values().get(value_index).is_none() {
                        return Err(IlError::range_out_of_bounds(
                            operand.value(),
                            body.values().len(),
                        ));
                    }

                    if !block_def[block_index][value_index] {
                        block_use[block_index][value_index] = true;
                    }
                }

                for (result_index, defined) in block_def[block_index]
                    .iter_mut()
                    .enumerate()
                    .take(operation.results().end())
                    .skip(operation.results().start())
                {
                    if body.values().get(result_index).is_none() {
                        return Err(IlError::range_out_of_bounds(
                            u32::try_from(result_index).unwrap_or(u32::MAX),
                            body.values().len(),
                        ));
                    }

                    *defined = true;
                }
            }
        }

        Ok(())
    }

    fn pack_sets(sets: &[Vec<bool>]) -> Result<(Vec<u32>, Vec<ValueId>), IlError> {
        let mut offsets = Vec::with_capacity(sets.len() + 1);
        let mut values = Vec::new();

        offsets.push(0);

        for set in sets {
            for (value_index, live) in set.iter().enumerate() {
                if *live {
                    values.push(ValueId::try_from_index(value_index)?);
                }
            }

            offsets.push(
                u32::try_from(values.len())
                    .map_err(|_| IlError::integer_overflow("SSA liveness offset"))?,
            );
        }

        Ok((offsets, values))
    }

    fn values_for<'a>(block: BlockId, offsets: &[u32], values: &'a [ValueId]) -> &'a [ValueId] {
        let index = block.index();
        let Some(start) = offsets.get(index).copied() else {
            return &[];
        };
        let end = offsets.get(index + 1).copied().unwrap_or(start);

        &values[start as usize..end as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{
        ArtefactHeader, Block, BuildStatus, CommonBody, Finish, IrLevel, PackedRange,
    };
    use crate::il::llil::ssa::{LLIL_SSA_SCHEMA_VERSION, SsaBuilder, SsaOpcode, SsaOperation};
    use crate::ir::FunctionId;

    #[test]
    fn liveness_tracks_value_across_linear_edge() {
        let block0 = BlockId::try_from_index(0).unwrap();
        let block1 = BlockId::try_from_index(1).unwrap();
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let common = CommonBody::new(
            vec![
                Block::new(
                    PackedRange::new(0, 1).unwrap(),
                    PackedRange::new(0, 1).unwrap(),
                    Block::ENTRY,
                ),
                Block::new(
                    PackedRange::new(1, 2).unwrap(),
                    PackedRange::EMPTY,
                    Block::EXIT,
                ),
            ],
            vec![block1],
            Vec::new(),
            Vec::new(),
        );
        let mut builder = SsaBuilder::new(header, common);
        let (value, results) = builder.push_result_value(64).unwrap();

        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Constant,
                results,
                PackedRange::EMPTY,
                64,
            ))
            .unwrap();

        let operands = builder.push_value_operands([value]).unwrap();

        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Return,
                PackedRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let body = builder.finish(&BuildStatus::new()).unwrap();
        let liveness = Liveness::build(&body).unwrap();

        assert_eq!(liveness.live_in(block0), &[]);
        assert_eq!(liveness.live_out(block0), &[value]);
        assert_eq!(liveness.live_in(block1), &[value]);
        assert_eq!(liveness.live_out(block1), &[]);
    }

    #[test]
    fn liveness_ignores_value_defined_before_same_block_use() {
        let block = BlockId::try_from_index(0).unwrap();
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let common = CommonBody::new(
            vec![Block::new(
                PackedRange::new(0, 2).unwrap(),
                PackedRange::EMPTY,
                Block::ENTRY | Block::EXIT,
            )],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut builder = SsaBuilder::new(header, common);
        let (value, results) = builder.push_result_value(32).unwrap();

        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Constant,
                results,
                PackedRange::EMPTY,
                32,
            ))
            .unwrap();

        let operands = builder.push_value_operands([value]).unwrap();

        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Return,
                PackedRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let body = builder.finish(&BuildStatus::new()).unwrap();
        let liveness = Liveness::build(&body).unwrap();

        assert_eq!(liveness.live_in(block), &[]);
        assert_eq!(liveness.live_out(block), &[]);
    }

    #[test]
    fn liveness_treats_block_argument_as_entry_definition() {
        let block = BlockId::try_from_index(0).unwrap();
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let common = CommonBody::new(
            vec![Block::new(
                PackedRange::new(0, 1).unwrap(),
                PackedRange::EMPTY,
                Block::ENTRY | Block::EXIT,
            )],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut builder = SsaBuilder::new(header, common);
        let argument = builder.push_block_argument_value(block, 32).unwrap();
        let operands = builder.push_value_operands([argument]).unwrap();

        builder
            .push_operation(SsaOperation::new(
                SsaOpcode::Return,
                PackedRange::EMPTY,
                operands,
                0,
            ))
            .unwrap();

        let body = builder.finish(&BuildStatus::new()).unwrap();
        let liveness = Liveness::build(&body).unwrap();

        assert_eq!(liveness.live_in(block), &[]);
        assert_eq!(liveness.live_out(block), &[]);
    }
}
