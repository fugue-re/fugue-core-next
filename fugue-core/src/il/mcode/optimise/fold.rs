use fugue_bv::BitVec;
use smallvec::SmallVec;

use crate::il::common::{IlArtefact, IlCsr, IlOpId, IlRewrite, IlValueId};
use crate::il::mcode::{MCodeBlockArgInputs, MCodeIr, MCodeOpcode, MCodeUses};

pub(crate) struct MCodeConstantFolding;

impl IlRewrite<MCodeIr> for MCodeConstantFolding {
    fn rewrite(&mut self, ir: &mut MCodeIr) {
        let uses = ir.analyse::<MCodeUses>();
        let inputs = ir.analyse::<MCodeBlockArgInputs>();
        let dependent_args = IlCsr::from_entries(
            ir.values().len(),
            inputs.iter().flat_map(|(arg, arg_inputs)| {
                arg_inputs.iter().map(move |input| (input.index(), arg))
            }),
        );
        let mut folded = vec![None::<BitVec>; ir.values().len()];
        let mut worklist = Vec::new();

        for operation in ir.ops() {
            if operation.results().len() != 1 || operation.opcode() != MCodeOpcode::Constant {
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
                let operation = &ir.ops()[user.index()];
                if operation.results().len() != 1 || operation.opcode() == MCodeOpcode::Constant {
                    continue;
                }
                let result = operation.results().start();
                if folded[result].is_some() || ir.values()[result].width() != operation.width() {
                    continue;
                }
                let operation_operands = ir.op_operands_for(operation);
                let mut operands = SmallVec::<[&BitVec; 4]>::new();
                for operand in operation_operands {
                    let Some(constant) = folded[operand.index()].as_ref() else {
                        break;
                    };
                    operands.push(constant);
                }
                if operands.len() != operation_operands.len() {
                    continue;
                }
                let value = if operation.opcode() == MCodeOpcode::SetVar {
                    operands
                        .first()
                        .map(|value| (*value).clone().cast(operation.width()))
                } else {
                    operation.opcode().evaluate(operation.width(), &operands)
                };
                let Some(value) = value else {
                    continue;
                };
                drop(operands);
                folded[result] = Some(value);
                worklist.push(result);
            }

            for &arg in dependent_args.row(value_index) {
                let result = arg.index();
                if folded[result].is_some() {
                    continue;
                }
                let arg_inputs = inputs
                    .inputs_for(arg)
                    .expect("dependent argument has recorded inputs");
                let Some(first) = arg_inputs.first() else {
                    continue;
                };
                let Some(value) = folded[first.index()].clone() else {
                    continue;
                };
                if arg_inputs
                    .iter()
                    .all(|input| folded[input.index()].as_ref() == Some(&value))
                {
                    folded[result] = Some(value);
                    worklist.push(result);
                }
            }
        }

        let mut rewriter = ir.rewriter();
        for index in 0..rewriter.ops().len() {
            let operation = &rewriter.ops()[index];
            if operation.opcode() == MCodeOpcode::Constant || operation.results().len() != 1 {
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
