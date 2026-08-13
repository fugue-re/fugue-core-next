use fixedbitset::FixedBitSet;

use crate::il::common::{IlAnalysis, IlArtefact, IlBlockArgId, IlOpId, IlSsaDef, IlValueId};
use crate::il::ecode::ssa::{ECodeSsaBlockArgInputs, ECodeSsaIr};

pub(crate) struct ECodeSsaRequiredDefs {
    required_block_arguments: FixedBitSet,
    required_operations: FixedBitSet,
}

#[derive(Clone, Copy)]
enum RequiredDef {
    BlockArgument(IlBlockArgId),
    Operation(IlOpId),
}

impl ECodeSsaRequiredDefs {
    fn new(ir: &ECodeSsaIr) -> Self {
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
        for index in 0..ir.values().len() {
            let value =
                IlValueId::try_from_index(index).expect("value count fits the value id space");
            if ir.value_domain(value).is_some() {
                required.mark_value_required(ir, value, &mut worklist);
            }
        }

        let inputs = ir.analyse::<ECodeSsaBlockArgInputs>();
        while let Some(entity) = worklist.pop() {
            match entity {
                RequiredDef::Operation(operation) => {
                    let operation = &ir.operations()[operation.index()];
                    for &operand in ir.operation_operands_for(operation) {
                        required.mark_value_required(ir, operand, &mut worklist);
                    }
                }
                RequiredDef::BlockArgument(argument) => {
                    let value = ir.block_arguments()[argument.index()].value();
                    if let Some(argument_inputs) = inputs.inputs_for(value) {
                        for &input in argument_inputs {
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
        ir: &ECodeSsaIr,
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
}

impl IlAnalysis<ECodeSsaIr> for ECodeSsaRequiredDefs {
    fn analyse(ir: &ECodeSsaIr) -> Self {
        Self::new(ir)
    }
}

impl ECodeSsaRequiredDefs {
    pub(crate) fn block_argument_is_required(&self, index: usize) -> bool {
        self.required_block_arguments.contains(index)
    }

    pub(crate) fn operation_is_required(&self, index: usize) -> bool {
        self.required_operations.contains(index)
    }
}
