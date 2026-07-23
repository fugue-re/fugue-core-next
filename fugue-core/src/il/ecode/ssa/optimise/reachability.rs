use crate::il::common::{IlAnalysis, IlArtefact, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaBlockArgumentInputs, ECodeSsaIr, ECodeSsaValueKind};

pub(crate) struct ECodeSsaReachability {
    block_arguments: Vec<bool>,
    operations: Vec<bool>,
}

#[derive(Clone, Copy)]
enum ReachableEntity {
    BlockArgument(usize),
    Operation(usize),
}

struct ECodeSsaReachabilityBuilder {
    block_arguments: Vec<bool>,
    operations: Vec<bool>,
    worklist: Vec<ReachableEntity>,
}

impl ECodeSsaReachabilityBuilder {
    fn new(body: &ECodeSsaIr) -> Self {
        let mut this = Self {
            block_arguments: vec![false; body.block_arguments.len()],
            operations: vec![false; body.operations.len()],
            worklist: Vec::new(),
        };
        for (index, operation) in body.operations.iter().enumerate() {
            if operation.opcode().is_dce_root() {
                this.operations[index] = true;
                this.worklist.push(ReachableEntity::Operation(index));
            }
        }
        this
    }

    fn build(mut self, body: &ECodeSsaIr) -> ECodeSsaReachability {
        let inputs = body.analyse::<ECodeSsaBlockArgumentInputs>();
        while let Some(entity) = self.worklist.pop() {
            match entity {
                ReachableEntity::Operation(operation_index) => {
                    let operands = body.operations[operation_index].operands();
                    for &operand in operands.slice(&body.value_operands) {
                        self.mark_value_reachable(body, operand);
                    }
                }
                ReachableEntity::BlockArgument(argument_index) => {
                    let value = body.block_arguments[argument_index].value();
                    if let Some(argument_inputs) = inputs.get(value) {
                        for &input in argument_inputs {
                            self.mark_value_reachable(body, input);
                        }
                    }
                }
            }
        }

        ECodeSsaReachability {
            block_arguments: self.block_arguments,
            operations: self.operations,
        }
    }

    fn mark_value_reachable(&mut self, body: &ECodeSsaIr, value: IlValueId) {
        let Some(record) = body.values.get(value.index()) else {
            return;
        };
        let index = record.definition_index() as usize;
        match record.definition_kind() {
            ECodeSsaValueKind::Operation => {
                if !self.operations[index] {
                    self.operations[index] = true;
                    self.worklist.push(ReachableEntity::Operation(index));
                }
            }
            ECodeSsaValueKind::BlockArgument => {
                if !self.block_arguments[index] {
                    self.block_arguments[index] = true;
                    self.worklist.push(ReachableEntity::BlockArgument(index));
                }
            }
        }
    }
}

impl IlAnalysis<ECodeSsaIr> for ECodeSsaReachability {
    fn analyse(body: &ECodeSsaIr) -> Self {
        ECodeSsaReachabilityBuilder::new(body).build(body)
    }
}

impl ECodeSsaReachability {
    pub(crate) fn block_argument_is_reachable(&self, index: usize) -> bool {
        self.block_arguments[index]
    }

    pub(crate) fn operation_is_reachable(&self, index: usize) -> bool {
        self.operations[index]
    }
}
