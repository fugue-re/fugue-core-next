use crate::il::common::verify::{
    VerifyError, checked_slice, verify_bounds, verify_graph, verify_graph_bounds,
    verify_parent_spans, verify_source_spans,
};
use crate::il::common::{IlArtefact, IlBlockId, IlDominance, IlError, IlLevel, IlOpId, IlValueId};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArg, ECodeSsaIr, ECodeSsaOp, ECodeSsaOpcode, ECodeSsaValueKind,
};

#[cfg(test)]
#[path = "verify/test.rs"]
mod test;

pub(crate) fn verify(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
    if ir.header().schema() != ECodeSsaIr::SCHEMA {
        return Err(IlError::schema_mismatch(
            ECodeSsaIr::LEVEL,
            ECodeSsaIr::SCHEMA.value(),
            ir.header().schema().value(),
        )
        .into());
    }

    verify_graph(ir.graph())?;
    verify_graph_bounds(ir.graph(), ir.operations().len())?;
    verify_source_spans(ir.source_spans(), ir.operations().len())?;
    verify_parent_spans(ir.parent_spans(), ir.operations().len())?;
    verify_memory_domains(ir)?;
    verify_edge_arguments(ir)?;

    for (argument_index, argument) in ir.block_arguments().iter().enumerate() {
        ir.graph()
            .blocks()
            .get(argument.block().index())
            .ok_or(IlError::range_out_of_bounds(
                argument.block().value(),
                ir.graph().blocks().len(),
            ))?;

        ir.values()
            .get(argument.value().index())
            .ok_or(IlError::range_out_of_bounds(
                argument.value().value(),
                ir.values().len(),
            ))?;

        let value = ir.values()[argument.value().index()];

        if value.definition_kind() != ECodeSsaValueKind::BlockArgument
            || value.definition_index() != argument_index as u32
            || value.width() != argument.width()
        {
            return Err(VerifyError::InvalidValueDefinition {
                level: IlLevel::ECodeSsa,
            });
        }
    }

    for (operation_index, operation) in ir.operations().iter().enumerate() {
        verify_bounds(operation.results(), ir.values().len())?;
        verify_bounds(operation.operands(), ir.value_operands().len())?;

        for result_index in operation.results().start()..operation.results().end() {
            let value = ir.values()[result_index];

            if value.definition_kind() != ECodeSsaValueKind::Operation
                || value.definition_index() != operation_index as u32
            {
                return Err(VerifyError::InvalidValueDefinition {
                    level: IlLevel::ECodeSsa,
                });
            }

            if value.width() != operation.width() {
                return Err(IlError::width_mismatch(IlLevel::ECodeSsa).into());
            }
        }

        if operation.opcode() == ECodeSsaOpcode::Constant && operation.width() > 64 {
            let bytes = operation.width().div_ceil(8) as usize;
            let end = (operation.immediate() as usize).saturating_add(bytes);
            if end > ir.constant_storage().len() {
                return Err(IlError::range_out_of_bounds(
                    u32::try_from(end).unwrap_or(u32::MAX),
                    ir.constant_storage().len(),
                )
                .into());
            }
        }

        let uniform_operand_width = operation.opcode().has_uniform_operand_width();
        for operand in checked_slice(operation.operands(), ir.value_operands())? {
            let value = ir
                .values()
                .get(operand.index())
                .ok_or(IlError::range_out_of_bounds(
                    operand.value(),
                    ir.values().len(),
                ))?;

            if uniform_operand_width && value.width() != operation.width() {
                return Err(IlError::width_mismatch(IlLevel::ECodeSsa).into());
            }
        }

        if operation.opcode().requires_memory_domain() {
            let Some(address_space) = operation.address_space() else {
                return Err(IlError::missing_component(IlLevel::ECodeSsa, "memory domain").into());
            };

            if ir.memory_domain(address_space).is_none() {
                return Err(IlError::missing_component(IlLevel::ECodeSsa, "memory domain").into());
            }

            verify_memory_operation(ir, operation)?;
        }
    }

    for (value_index, value) in ir.values().iter().enumerate() {
        let value_id = IlValueId::try_from_index(value_index)?;

        match value.definition_kind() {
            ECodeSsaValueKind::Operation => {
                let Some(operation) = ir.operations().get(value.definition_index() as usize) else {
                    return Err(VerifyError::InvalidValueDefinition {
                        level: IlLevel::ECodeSsa,
                    });
                };

                if !operation.results().contains_index(value_id.index()) {
                    return Err(VerifyError::InvalidValueDefinition {
                        level: IlLevel::ECodeSsa,
                    });
                }
            }
            ECodeSsaValueKind::BlockArgument => {
                let Some(argument) = ir.block_arguments().get(value.definition_index() as usize)
                else {
                    return Err(VerifyError::InvalidValueDefinition {
                        level: IlLevel::ECodeSsa,
                    });
                };

                if argument.value() != value_id || argument.width() != value.width() {
                    return Err(VerifyError::InvalidValueDefinition {
                        level: IlLevel::ECodeSsa,
                    });
                }
            }
        }
    }

    verify_dominating_uses(ir)?;

    Ok(())
}

fn verify_memory_domains(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
    for (index, domain) in ir.memory_domains().iter().enumerate() {
        if ir.memory_domains()[..index]
            .iter()
            .any(|existing| existing.space() == domain.space())
        {
            return Err(VerifyError::DuplicateMemoryDomain {
                level: IlLevel::ECodeSsa,
            });
        }
    }

    Ok(())
}

fn verify_memory_operation(ir: &ECodeSsaIr, operation: &ECodeSsaOp) -> Result<(), VerifyError> {
    let operands = ir.operation_operands(operation);
    let Some(memory) = operands.last() else {
        return Err(IlError::missing_component(IlLevel::ECodeSsa, "memory domain").into());
    };
    let memory = ir.values()[memory.index()];

    if memory.width() != 0 {
        return Err(IlError::width_mismatch(IlLevel::ECodeSsa).into());
    }

    if operation.opcode() == ECodeSsaOpcode::Store {
        if operation.results().len() != 1 {
            return Err(IlError::missing_component(IlLevel::ECodeSsa, "memory domain").into());
        }

        let result = ir.values()[operation.results().start()];

        if result.width() != 0 {
            return Err(IlError::width_mismatch(IlLevel::ECodeSsa).into());
        }
    }

    Ok(())
}

fn verify_edge_arguments(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
    if ir.edge_arguments().len() != ir.graph().successors().len() {
        return Err(VerifyError::BlockArgumentCount {
            block: 0,
            expected: ir.graph().successors().len(),
            found: ir.edge_arguments().len(),
        });
    }

    for range in ir.edge_arguments() {
        verify_bounds(*range, ir.edge_argument_values().len())?;
    }

    for value in ir.edge_argument_values() {
        ir.values()
            .get(value.index())
            .ok_or(IlError::range_out_of_bounds(
                value.value(),
                ir.values().len(),
            ))?;
    }

    Ok(())
}

fn verify_dominating_uses(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
    if ir.graph().blocks().is_empty() {
        return verify_linear_dominating_uses(ir);
    }

    let operation_blocks = operation_blocks(ir)?;
    let dominance = ir.analyse::<IlDominance>();

    verify_edge_argument_uses(ir, &operation_blocks, &dominance)?;

    for (operation_index, operation) in ir.operations().iter().enumerate() {
        let operation_id = IlOpId::try_from_index(operation_index)?;
        let Some(user_block) = operation_blocks[operation_index] else {
            return Err(VerifyError::InvalidOperationPlacement {
                level: IlLevel::ECodeSsa,
                operation: operation_id.value(),
            });
        };

        if !dominance.is_reachable(user_block) {
            continue;
        }

        for operand in ir.operation_operands(operation) {
            if !value_dominates_operation(
                ir,
                *operand,
                user_block,
                operation_index,
                &operation_blocks,
                &dominance,
            )? {
                return Err(VerifyError::NonDominatingUse {
                    level: IlLevel::ECodeSsa,
                    value: operand.value(),
                    user: operation_id.value(),
                });
            }
        }
    }

    Ok(())
}

fn verify_edge_argument_uses(
    ir: &ECodeSsaIr,
    operation_blocks: &[Option<IlBlockId>],
    dominance: &IlDominance,
) -> Result<(), VerifyError> {
    for (predecessor_index, predecessor) in ir.graph().blocks().iter().enumerate() {
        let predecessor_id = IlBlockId::try_from_index(predecessor_index)?;

        for (successor_offset, successor) in
            checked_slice(predecessor.successors(), ir.graph().successors())?
                .iter()
                .enumerate()
        {
            let edge = predecessor.successors().start() + successor_offset;
            let arguments = ir.arguments_for_edge(edge);
            let block_arguments = block_arguments_for_block(ir, *successor);

            if arguments.len() != block_arguments.len() {
                return Err(VerifyError::BlockArgumentCount {
                    block: successor.value(),
                    expected: block_arguments.len(),
                    found: arguments.len(),
                });
            }

            if !dominance.is_reachable(predecessor_id) {
                continue;
            }

            for (value, argument) in arguments.iter().zip(block_arguments) {
                let incoming = ir.values()[value.index()];

                if incoming.width() != argument.width() {
                    return Err(IlError::width_mismatch(IlLevel::ECodeSsa).into());
                }

                if !value_dominates_edge(ir, *value, predecessor_id, operation_blocks, dominance)? {
                    return Err(VerifyError::NonDominatingEdgeArgument {
                        level: IlLevel::ECodeSsa,
                        value: value.value(),
                        predecessor: predecessor_id.value(),
                        successor: successor.value(),
                    });
                }
            }
        }
    }

    Ok(())
}

fn block_arguments_for_block(ir: &ECodeSsaIr, block: IlBlockId) -> Vec<ECodeSsaBlockArg> {
    ir.block_arguments()
        .iter()
        .copied()
        .filter(|argument| argument.block() == block)
        .collect()
}

fn verify_linear_dominating_uses(ir: &ECodeSsaIr) -> Result<(), VerifyError> {
    for (operation_index, operation) in ir.operations().iter().enumerate() {
        let operation_id = IlOpId::try_from_index(operation_index)?;

        for operand in ir.operation_operands(operation) {
            let value = ir.values()[operand.index()];

            if value.definition_kind() == ECodeSsaValueKind::Operation
                && value.definition_index() as usize >= operation_index
            {
                return Err(VerifyError::NonDominatingUse {
                    level: IlLevel::ECodeSsa,
                    value: operand.value(),
                    user: operation_id.value(),
                });
            }
        }
    }

    Ok(())
}

fn operation_blocks(ir: &ECodeSsaIr) -> Result<Vec<Option<IlBlockId>>, VerifyError> {
    let mut operation_blocks = vec![None; ir.operations().len()];

    for (block_index, block) in ir.graph().blocks().iter().enumerate() {
        let block_id = IlBlockId::try_from_index(block_index)?;
        verify_bounds(block.operations(), ir.operations().len())?;

        for (operation_index, operation_block) in operation_blocks
            .iter_mut()
            .enumerate()
            .take(block.operations().end())
            .skip(block.operations().start())
        {
            if operation_block.is_some() {
                let operation_id = IlOpId::try_from_index(operation_index)?;
                return Err(VerifyError::InvalidOperationPlacement {
                    level: IlLevel::ECodeSsa,
                    operation: operation_id.value(),
                });
            }

            *operation_block = Some(block_id);
        }
    }

    Ok(operation_blocks)
}

fn value_dominates_operation(
    ir: &ECodeSsaIr,
    value_id: IlValueId,
    user_block: IlBlockId,
    user_operation: usize,
    operation_blocks: &[Option<IlBlockId>],
    dominance: &IlDominance,
) -> Result<bool, VerifyError> {
    let value = ir.values()[value_id.index()];

    match value.definition_kind() {
        ECodeSsaValueKind::Operation => {
            let definition_operation = value.definition_index() as usize;
            let Some(definition_block) = operation_blocks
                .get(definition_operation)
                .copied()
                .flatten()
            else {
                let operation_id = IlOpId::try_from_index(definition_operation)?;
                return Err(VerifyError::InvalidOperationPlacement {
                    level: IlLevel::ECodeSsa,
                    operation: operation_id.value(),
                });
            };

            if definition_block == user_block {
                Ok(definition_operation < user_operation)
            } else {
                Ok(dominance.dominates(definition_block, user_block))
            }
        }
        ECodeSsaValueKind::BlockArgument => {
            let argument = ir.block_arguments()[value.definition_index() as usize];

            Ok(dominance.dominates(argument.block(), user_block))
        }
    }
}

fn value_dominates_edge(
    ir: &ECodeSsaIr,
    value_id: IlValueId,
    predecessor: IlBlockId,
    operation_blocks: &[Option<IlBlockId>],
    dominance: &IlDominance,
) -> Result<bool, VerifyError> {
    let value = ir.values()[value_id.index()];

    match value.definition_kind() {
        ECodeSsaValueKind::Operation => {
            let definition_operation = value.definition_index() as usize;
            let Some(definition_block) = operation_blocks
                .get(definition_operation)
                .copied()
                .flatten()
            else {
                let operation_id = IlOpId::try_from_index(definition_operation)?;
                return Err(VerifyError::InvalidOperationPlacement {
                    level: IlLevel::ECodeSsa,
                    operation: operation_id.value(),
                });
            };

            Ok(definition_block == predecessor
                || dominance.dominates(definition_block, predecessor))
        }
        ECodeSsaValueKind::BlockArgument => {
            let argument = ir.block_arguments()[value.definition_index() as usize];

            Ok(dominance.dominates(argument.block(), predecessor))
        }
    }
}
