use fugue_bv::BitVec;

use crate::il::common::{IlArtefact, IlRewrite, IlValueId};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArgumentInputs, ECodeSsaConstantInterner, ECodeSsaIr, ECodeSsaOpcode, ECodeSsaUses,
};

pub(crate) struct ECodeSsaConstantFolding;

impl IlRewrite<ECodeSsaIr> for ECodeSsaConstantFolding {
    fn rewrite(&mut self, ir: &mut ECodeSsaIr) {
        let uses = ir.analyse::<ECodeSsaUses>();
        let inputs = ir.analyse::<ECodeSsaBlockArgumentInputs>();
        let mut dependent_arguments = vec![Vec::<IlValueId>::new(); ir.values.len()];
        for (argument, argument_inputs) in inputs.iter() {
            for input in argument_inputs {
                dependent_arguments[input.index()].push(argument);
            }
        }

        let mut folded = vec![None::<BitVec>; ir.values.len()];
        let mut worklist = Vec::new();
        let mut operands = Vec::new();

        for op in &ir.operations {
            if op.results().len() != 1 || !matches!(op.opcode(), ECodeSsaOpcode::Constant) {
                continue;
            }
            if let Some(value) = op.constant(&ir.constants) {
                let result = op.results().start();
                folded[result] = Some(value);
                worklist.push(result);
            }
        }

        while let Some(value_index) = worklist.pop() {
            let defined =
                IlValueId::try_from_index(value_index).expect("value id is representable");

            for used in uses.uses_for(defined) {
                let op = &ir.operations[used.user().index()];
                if op.results().len() != 1 || matches!(op.opcode(), ECodeSsaOpcode::Constant) {
                    continue;
                }
                let result = op.results().start();
                if folded[result].is_some() {
                    continue;
                }
                operands.clear();
                if op.operands().slice(&ir.value_operands).iter().all(|value| {
                    match &folded[value.index()] {
                        Some(constant) => {
                            operands.push(constant.clone());
                            true
                        }
                        None => false,
                    }
                }) && let Some(value) = op.opcode().evaluate(op.width(), &operands)
                {
                    folded[result] = Some(value);
                    worklist.push(result);
                }
            }

            for &argument in &dependent_arguments[value_index] {
                let result = argument.index();
                if folded[result].is_some() {
                    continue;
                }
                let argument_inputs = inputs
                    .get(argument)
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

        let mut constants = ECodeSsaConstantInterner::new(&mut ir.constants);
        constants.seed(&ir.operations);
        for op_index in 0..ir.operations.len() {
            let op = &ir.operations[op_index];
            if matches!(op.opcode(), ECodeSsaOpcode::Constant) || op.results().len() != 1 {
                continue;
            }
            let result = op.results().start();
            let Some(value) = folded[result].clone() else {
                continue;
            };
            let immediate = constants.intern(&value);
            ir.operations[op_index].replace_with_constant(immediate);
        }
    }
}
