use fixedbitset::FixedBitSet;

use crate::il::common::{IlArtefact, IlBlockArgId, IlOpId, IlSsaDef, IlValueId};
use crate::il::mcode::ssa::{MCodeSsaBlockArgInputs, MCodeSsaIr};

pub(super) struct MCodeSsaRequiredDefs {
    required_block_arguments: FixedBitSet,
    required_operations: FixedBitSet,
}

#[derive(Debug, Copy, Clone)]
enum RequiredDef {
    BlockArgument(IlBlockArgId),
    Operation(IlOpId),
}

impl MCodeSsaRequiredDefs {
    pub(super) fn new(ir: &MCodeSsaIr, required_values: &[IlValueId]) -> Self {
        let mut required = Self {
            required_block_arguments: FixedBitSet::with_capacity(ir.block_arguments().len()),
            required_operations: FixedBitSet::with_capacity(ir.operations().len()),
        };
        let mut worklist = Vec::new();
        for (index, operation) in ir.operations().iter().enumerate() {
            if operation.opcode().has_side_effect() {
                required.required_operations.insert(index);
                worklist.push(RequiredDef::Operation(
                    IlOpId::try_from_index(index).expect("operation id is representable"),
                ));
            }
        }
        for &value in required_values {
            required.mark_value_required(ir, value, &mut worklist);
        }

        let inputs = ir.analyse::<MCodeSsaBlockArgInputs>();
        while let Some(entity) = worklist.pop() {
            match entity {
                RequiredDef::Operation(operation) => {
                    let operation = &ir.operations()[operation.index()];
                    if let Some(variable) = operation.variable()
                        && !operation
                            .results()
                            .slice(ir.values())
                            .iter()
                            .any(|value| value.variable() == Some(variable))
                        && let Some(value) = ir.versions_of(variable).next()
                    {
                        required.mark_value_required(ir, value, &mut worklist);
                    }
                    for &operand in ir.operation_operands_for(operation) {
                        required.mark_value_required(ir, operand, &mut worklist);
                    }
                }
                RequiredDef::BlockArgument(argument) => {
                    let value = ir.block_arguments()[argument.index()].value();
                    if let Some(values) = inputs.inputs_for(value) {
                        for &input in values {
                            required.mark_value_required(ir, input, &mut worklist);
                        }
                    }
                }
            }
        }

        required
    }

    fn mark_value_required(
        &mut self,
        ir: &MCodeSsaIr,
        value: IlValueId,
        worklist: &mut Vec<RequiredDef>,
    ) {
        let Some(record) = ir.values().get(value.index()) else {
            return;
        };
        match record.definition() {
            IlSsaDef::Operation(operation) => {
                if !self.required_operations.put(operation.index()) {
                    worklist.push(RequiredDef::Operation(operation));
                }
            }
            IlSsaDef::BlockArgument(argument) => {
                if !self.required_block_arguments.put(argument.index()) {
                    worklist.push(RequiredDef::BlockArgument(argument));
                }
            }
        }
    }

    pub(super) fn block_argument_is_required(&self, index: usize) -> bool {
        self.required_block_arguments.contains(index)
    }

    pub(super) fn operation_is_required(&self, index: usize) -> bool {
        self.required_operations.contains(index)
    }
}
