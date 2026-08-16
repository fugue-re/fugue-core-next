use crate::il::common::{IlArtefact, IlOpId, IlRequiredDefs, IlSsaDef, IlValueId};
use crate::il::mcode::{MCodeBlockArgInputs, MCodeIr};

pub(crate) struct MCodeRequiredDefs {
    definitions: IlRequiredDefs,
}

impl MCodeRequiredDefs {
    pub(crate) fn new(ir: &MCodeIr, required_values: &[IlValueId]) -> Self {
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
        for &value in required_values {
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

        let mut first_values = vec![None; ir.variables().len()];
        for (index, value) in ir.values().iter().enumerate() {
            let Some(variable) = value.variable() else {
                continue;
            };
            let Some(first) = first_values.get_mut(variable.index()) else {
                continue;
            };
            if first.is_none() {
                *first = Some(
                    IlValueId::try_from_index(index).expect("value count fits the value id space"),
                );
            }
        }

        let inputs = ir.analyse::<MCodeBlockArgInputs>();
        while let Some(entity) = worklist.pop() {
            match entity {
                IlSsaDef::Operation(operation) => {
                    let operation = &ir.operations()[operation.index()];
                    let predecessor = operation
                        .variable()
                        .filter(|variable| {
                            !operation
                                .results()
                                .slice(ir.values())
                                .iter()
                                .any(|value| value.variable() == Some(*variable))
                        })
                        .and_then(|variable| first_values.get(variable.index()).copied().flatten())
                        .and_then(|value| {
                            ir.values()
                                .get(value.index())
                                .map(|value| value.definition())
                        });
                    if let Some(definition) = predecessor
                        && required.definitions.mark(definition)
                    {
                        worklist.push(definition);
                    }
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
                    let Some(values) = inputs.inputs_for(value) else {
                        continue;
                    };
                    for &input in values {
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
