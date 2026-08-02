use fixedbitset::FixedBitSet;

use crate::il::common::{IlAnalysis, IlArtefact, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaBlockArgumentInputs, ECodeSsaIr, ECodeSsaValueKind};

pub(crate) struct ECodeSsaRequiredDefinitions {
    required_block_arguments: FixedBitSet,
    required_operations: FixedBitSet,
}

#[derive(Clone, Copy)]
enum RequiredEntity {
    BlockArgument(usize),
    Operation(usize),
}

struct ECodeSsaRequiredDefinitionsBuilder {
    required_block_arguments: FixedBitSet,
    required_operations: FixedBitSet,
    worklist: Vec<RequiredEntity>,
}

impl ECodeSsaRequiredDefinitionsBuilder {
    fn new(ir: &ECodeSsaIr) -> Self {
        let mut this = Self {
            required_block_arguments: FixedBitSet::with_capacity(ir.block_arguments().len()),
            required_operations: FixedBitSet::with_capacity(ir.operations().len()),
            worklist: Vec::new(),
        };
        for (index, operation) in ir.operations().iter().enumerate() {
            if operation.opcode().has_side_effect() {
                this.required_operations.insert(index);
                this.worklist.push(RequiredEntity::Operation(index));
            }
        }
        this
    }

    fn build(mut self, ir: &ECodeSsaIr) -> ECodeSsaRequiredDefinitions {
        let inputs = ir.analyse::<ECodeSsaBlockArgumentInputs>();
        while let Some(entity) = self.worklist.pop() {
            match entity {
                RequiredEntity::Operation(operation_index) => {
                    let operation = &ir.operations()[operation_index];
                    for &operand in ir.operation_operands_for(operation) {
                        self.mark_value_required(ir, operand);
                    }
                }
                RequiredEntity::BlockArgument(argument_index) => {
                    let value = ir.block_arguments()[argument_index].value();
                    if let Some(argument_inputs) = inputs.inputs_for(value) {
                        for &input in argument_inputs {
                            self.mark_value_required(ir, input);
                        }
                    }
                }
            }
        }

        ECodeSsaRequiredDefinitions {
            required_block_arguments: self.required_block_arguments,
            required_operations: self.required_operations,
        }
    }

    fn mark_value_required(&mut self, ir: &ECodeSsaIr, value: IlValueId) {
        let Some(record) = ir.values().get(value.index()) else {
            return;
        };
        let index = record.definition_index() as usize;
        match record.definition_kind() {
            ECodeSsaValueKind::Operation => {
                if !self.required_operations.put(index) {
                    self.worklist.push(RequiredEntity::Operation(index));
                }
            }
            ECodeSsaValueKind::BlockArgument => {
                if !self.required_block_arguments.put(index) {
                    self.worklist.push(RequiredEntity::BlockArgument(index));
                }
            }
        }
    }
}

impl IlAnalysis<ECodeSsaIr> for ECodeSsaRequiredDefinitions {
    fn analyse(ir: &ECodeSsaIr) -> Self {
        ECodeSsaRequiredDefinitionsBuilder::new(ir).build(ir)
    }
}

impl ECodeSsaRequiredDefinitions {
    pub(crate) fn block_argument_is_required(&self, index: usize) -> bool {
        self.required_block_arguments.contains(index)
    }

    pub(crate) fn operation_is_required(&self, index: usize) -> bool {
        self.required_operations.contains(index)
    }
}
