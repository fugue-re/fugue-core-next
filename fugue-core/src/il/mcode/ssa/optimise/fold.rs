use fugue_bv::BitVec;
use smallvec::SmallVec;

use crate::il::common::{IlArtefact, IlCsr, IlOpId, IlRewrite, IlValueId};
use crate::il::mcode::ssa::{MCodeSsaBlockArgInputs, MCodeSsaIr, MCodeSsaOpcode, MCodeSsaUses};

pub(crate) struct MCodeSsaConstantFolding;

impl IlRewrite<MCodeSsaIr> for MCodeSsaConstantFolding {
    fn rewrite(&mut self, ir: &mut MCodeSsaIr) {
        let uses = ir.analyse::<MCodeSsaUses>();
        let inputs = ir.analyse::<MCodeSsaBlockArgInputs>();
        let dependent_arguments = IlCsr::from_entries(
            ir.values().len(),
            inputs.iter().flat_map(|(argument, argument_inputs)| {
                argument_inputs
                    .iter()
                    .map(move |input| (input.index(), argument))
            }),
        );
        let mut folded = vec![None::<BitVec>; ir.values().len()];
        let mut worklist = Vec::new();

        for operation in ir.operations() {
            if operation.results().len() != 1 || operation.opcode() != MCodeSsaOpcode::Constant {
                continue;
            }
            if let Some(value) = operation.constant(ir.constant_storage()) {
                let result = operation.results().start();
                folded[result] = Some(value);
                worklist.push(result);
            }
        }

        while let Some(value_index) = worklist.pop() {
            let defined = IlValueId::try_from_index(value_index)
                .expect("value count fits the value id space");
            for usage in uses.uses_for(defined) {
                let user = usage.user();
                let operation = &ir.operations()[user.index()];
                if operation.results().len() != 1 || operation.opcode() == MCodeSsaOpcode::Constant
                {
                    continue;
                }
                let result = operation.results().start();
                if folded[result].is_some() || ir.values()[result].width() != operation.width() {
                    continue;
                }
                let value = {
                    let mut operands = SmallVec::<[&BitVec; 4]>::new();
                    let all_constant = ir.operation_operands_for(operation).iter().all(|value| {
                        match &folded[value.index()] {
                            Some(constant) => {
                                operands.push(constant);
                                true
                            }
                            None => false,
                        }
                    });
                    if !all_constant {
                        None
                    } else if operation.opcode() == MCodeSsaOpcode::SetVar {
                        operands
                            .first()
                            .map(|value| (*value).clone().cast(operation.width()))
                    } else {
                        operation.opcode().evaluate(operation.width(), &operands)
                    }
                };
                if let Some(value) = value {
                    folded[result] = Some(value);
                    worklist.push(result);
                }
            }

            for &argument in dependent_arguments.row(value_index) {
                let result = argument.index();
                if folded[result].is_some() {
                    continue;
                }
                let argument_inputs = inputs
                    .inputs_for(argument)
                    .expect("dependent argument has recorded inputs");
                let Some(first) = argument_inputs.first() else {
                    continue;
                };
                let Some(value) = folded[first.index()].clone() else {
                    continue;
                };
                if argument_inputs
                    .iter()
                    .all(|input| folded[input.index()].as_ref() == Some(&value))
                {
                    folded[result] = Some(value);
                    worklist.push(result);
                }
            }
        }

        let mut rewriter = ir.rewriter();
        for index in 0..rewriter.operations().len() {
            let operation = &rewriter.operations()[index];
            if operation.opcode() == MCodeSsaOpcode::Constant || operation.results().len() != 1 {
                continue;
            }
            let result = operation.results().start();
            let Some(value) = folded[result].as_ref() else {
                continue;
            };
            let operation =
                IlOpId::try_from_index(index).expect("operation count fits the operation id space");
            rewriter.replace_with_constant(operation, value);
        }
    }
}
