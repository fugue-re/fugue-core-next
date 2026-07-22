use crate::il::common::IlValueId;
use crate::il::ecode::ssa::{ECodeSsaIr, ECodeSsaValueKind};

pub(crate) struct ECodeSsaReachability {
    pub(crate) operations: Vec<bool>,
    pub(crate) block_arguments: Vec<bool>,
}

#[derive(Clone, Copy)]
enum ReachableEntity {
    BlockArgument(usize),
    Operation(usize),
}

impl ECodeSsaIr {
    pub(crate) fn compute_reachability(&self) -> ECodeSsaReachability {
        let sources = self.block_argument_sources();
        let mut operations = vec![false; self.operations.len()];
        let mut block_arguments = vec![false; self.block_arguments.len()];
        let mut worklist = Vec::new();

        for (index, operation) in self.operations.iter().enumerate() {
            if operation.opcode().is_dce_root() {
                operations[index] = true;
                worklist.push(ReachableEntity::Operation(index));
            }
        }

        while let Some(entity) = worklist.pop() {
            match entity {
                ReachableEntity::Operation(operation_index) => {
                    let operands = self.operations[operation_index].operands();
                    for &operand in operands.slice(&self.value_operands) {
                        self.mark_value_reachable(
                            operand,
                            &mut operations,
                            &mut block_arguments,
                            &mut worklist,
                        );
                    }
                }
                ReachableEntity::BlockArgument(argument_index) => {
                    let value = self.block_arguments[argument_index].value();
                    if let Some(argument_sources) = sources.get(&value) {
                        for &source in argument_sources {
                            self.mark_value_reachable(
                                source,
                                &mut operations,
                                &mut block_arguments,
                                &mut worklist,
                            );
                        }
                    }
                }
            }
        }

        ECodeSsaReachability {
            operations,
            block_arguments,
        }
    }

    fn mark_value_reachable(
        &self,
        value: IlValueId,
        operations: &mut [bool],
        block_arguments: &mut [bool],
        worklist: &mut Vec<ReachableEntity>,
    ) {
        let Some(record) = self.values.get(value.index()) else {
            return;
        };
        let index = record.definition_index() as usize;
        match record.definition_kind() {
            ECodeSsaValueKind::Operation => {
                if !operations[index] {
                    operations[index] = true;
                    worklist.push(ReachableEntity::Operation(index));
                }
            }
            ECodeSsaValueKind::BlockArgument => {
                if !block_arguments[index] {
                    block_arguments[index] = true;
                    worklist.push(ReachableEntity::BlockArgument(index));
                }
            }
        }
    }
}
