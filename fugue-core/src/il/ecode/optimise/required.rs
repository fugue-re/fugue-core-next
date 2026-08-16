use crate::il::common::{IlAnalysis, IlArtefact, IlOpId, IlRequiredDefs, IlSsaDef, IlValueId};
use crate::il::ecode::{ECodeBlockArgInputs, ECodeIr};

pub(crate) struct ECodeRequiredDefs {
    definitions: IlRequiredDefs,
}

impl ECodeRequiredDefs {
    fn new(ir: &ECodeIr) -> Self {
        let mut required = Self {
            definitions: IlRequiredDefs::new(ir.block_args().len(), ir.operations().len()),
        };
        let mut worklist = Vec::new();
        for (index, operation) in ir.operations().iter().enumerate() {
            if operation.opcode().has_side_effect() {
                let definition = IlSsaDef::Operation(
                    IlOpId::try_from_index(index).expect("operation id is representable"),
                );
                required.definitions.mark(definition);
                worklist.push(definition);
            }
        }
        for index in 0..ir.values().len() {
            let value =
                IlValueId::try_from_index(index).expect("value count fits the value id space");
            if ir.value_domain(value).is_none() {
                continue;
            }
            let Some(definition) = ir
                .values()
                .get(value.index())
                .map(|value| value.definition())
            else {
                continue;
            };
            if required.definitions.mark(definition) {
                worklist.push(definition);
            }
        }

        let inputs = ir.analyse::<ECodeBlockArgInputs>();
        while let Some(entity) = worklist.pop() {
            match entity {
                IlSsaDef::Operation(operation) => {
                    let operation = &ir.operations()[operation.index()];
                    for &operand in ir.operation_operands_for(operation) {
                        let Some(definition) = ir
                            .values()
                            .get(operand.index())
                            .map(|value| value.definition())
                        else {
                            continue;
                        };
                        if required.definitions.mark(definition) {
                            worklist.push(definition);
                        }
                    }
                }
                IlSsaDef::BlockArg(arg) => {
                    let value = ir.block_args()[arg.index()].value();
                    let Some(arg_inputs) = inputs.inputs_for(value) else {
                        continue;
                    };
                    for &input in arg_inputs {
                        let Some(definition) = ir
                            .values()
                            .get(input.index())
                            .map(|value| value.definition())
                        else {
                            continue;
                        };
                        if required.definitions.mark(definition) {
                            worklist.push(definition);
                        }
                    }
                }
            }
        }

        required
    }

    pub(crate) fn block_arg_is_required(&self, index: usize) -> bool {
        self.definitions.block_arg_is_required(index)
    }

    pub(crate) fn operation_is_required(&self, index: usize) -> bool {
        self.definitions.operation_is_required(index)
    }
}

impl IlAnalysis<ECodeIr> for ECodeRequiredDefs {
    fn analyse(ir: &ECodeIr) -> Self {
        Self::new(ir)
    }
}
