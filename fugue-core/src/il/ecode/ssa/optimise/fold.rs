use fugue_bv::BitVec;
use smallvec::SmallVec;

use crate::il::common::{IlArtefact, IlCsr, IlOpId, IlRewrite, IlValueId};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArgumentInputs, ECodeSsaIr, ECodeSsaOpcode, ECodeSsaUses,
};

pub(crate) struct ECodeSsaConstantFolding;

impl IlRewrite<ECodeSsaIr> for ECodeSsaConstantFolding {
    fn rewrite(&mut self, ir: &mut ECodeSsaIr) {
        let uses = ir.analyse::<ECodeSsaUses>();
        let inputs = ir.analyse::<ECodeSsaBlockArgumentInputs>();
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

        for op in ir.operations() {
            if op.results().len() != 1 || !matches!(op.opcode(), ECodeSsaOpcode::Constant) {
                continue;
            }
            if let Some(value) = op.constant(ir.constant_storage()) {
                let result = op.results().start();
                folded[result] = Some(value);
                worklist.push(result);
            }
        }

        while let Some(value_index) = worklist.pop() {
            let defined =
                IlValueId::try_from_index(value_index).expect("value id is representable");

            for used in uses.uses_for(defined) {
                let op = &ir.operations()[used.user().index()];
                if op.results().len() != 1 || matches!(op.opcode(), ECodeSsaOpcode::Constant) {
                    continue;
                }
                let result = op.results().start();
                if folded[result].is_some() {
                    continue;
                }
                let value = {
                    let mut operands = SmallVec::<[&BitVec; 4]>::new();
                    let all_constant = ir.operation_operands_for(op).iter().all(|value| {
                        match &folded[value.index()] {
                            Some(constant) => {
                                operands.push(constant);
                                true
                            }
                            None => false,
                        }
                    });
                    if all_constant {
                        op.opcode().evaluate(op.width(), &operands)
                    } else {
                        None
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
            if matches!(operation.opcode(), ECodeSsaOpcode::Constant)
                || operation.results().len() != 1
            {
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
