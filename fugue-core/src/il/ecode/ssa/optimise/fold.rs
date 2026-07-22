use fugue_bv::BitVec;
use rustc_hash::FxHashMap;

use crate::il::common::IlValueId;
use crate::il::ecode::ssa::{ECodeSsaIr, ECodeSsaOpcode, ECodeSsaUses};

impl ECodeSsaIr {
    pub(crate) fn fold_constants(&mut self) {
        let uses = ECodeSsaUses::build(self);
        let sources = self.block_argument_sources();
        let mut dependent_arguments = vec![Vec::<IlValueId>::new(); self.values.len()];
        for (&argument, argument_sources) in &sources {
            for source in argument_sources {
                dependent_arguments[source.index()].push(argument);
            }
        }

        let mut folded = vec![None::<BitVec>; self.values.len()];
        let mut worklist = Vec::new();
        let mut operands = Vec::new();

        for op in &self.operations {
            if op.results().len() != 1 || !matches!(op.opcode(), ECodeSsaOpcode::Constant) {
                continue;
            }
            if let Some(value) = op.constant(&self.constants) {
                let result = op.results().start();
                folded[result] = Some(value);
                worklist.push(result);
            }
        }

        while let Some(value_index) = worklist.pop() {
            let defined =
                IlValueId::try_from_index(value_index).expect("value id is representable");

            for used in uses.uses_for(defined) {
                let op = &self.operations[used.user().index()];
                if op.results().len() != 1 || matches!(op.opcode(), ECodeSsaOpcode::Constant) {
                    continue;
                }
                let result = op.results().start();
                if folded[result].is_some() {
                    continue;
                }
                operands.clear();
                if op
                    .operands()
                    .slice(&self.value_operands)
                    .iter()
                    .all(|value| match &folded[value.index()] {
                        Some(constant) => {
                            operands.push(constant.clone());
                            true
                        }
                        None => false,
                    })
                    && let Some(value) = op.opcode().evaluate(op.width(), &operands)
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
                let argument_sources = &sources[&argument];
                let Some(first) = argument_sources.first() else {
                    continue;
                };
                let Some(value) = folded[first.index()].clone() else {
                    continue;
                };
                if argument_sources
                    .iter()
                    .all(|source| folded[source.index()].as_ref() == Some(&value))
                {
                    folded[result] = Some(value);
                    worklist.push(result);
                }
            }
        }

        let mut interned = self.seed_interned();
        for op_index in 0..self.operations.len() {
            let op = &self.operations[op_index];
            if matches!(op.opcode(), ECodeSsaOpcode::Constant) || op.results().len() != 1 {
                continue;
            }
            let result = op.results().start();
            let Some(value) = folded[result].clone() else {
                continue;
            };
            let immediate = self.intern_constant(&value, &mut interned);
            self.operations[op_index].replace_with_constant(immediate);
        }
    }

    fn intern_constant(&mut self, value: &BitVec, interned: &mut FxHashMap<Box<[u8]>, u64>) -> u64 {
        Self::intern_constant_into(value, &mut self.constants, interned)
    }

    pub(crate) fn intern_constant_into(
        value: &BitVec,
        constants: &mut Vec<u8>,
        interned: &mut FxHashMap<Box<[u8]>, u64>,
    ) -> u64 {
        let width_bytes = value.bits().div_ceil(8) as usize;
        if value.bits() <= 64 {
            let mut inline = [0u8; 8];
            value.to_le_bytes(&mut inline[..width_bytes]);
            return u64::from_le_bytes(inline);
        }

        let mut bytes = vec![0u8; width_bytes];
        value.to_le_bytes(&mut bytes);
        if let Some(&offset) = interned.get(bytes.as_slice()) {
            return offset;
        }
        let offset = constants.len() as u64;
        constants.extend_from_slice(&bytes);
        interned.insert(bytes.into_boxed_slice(), offset);
        offset
    }

    fn seed_interned(&self) -> FxHashMap<Box<[u8]>, u64> {
        let mut interned = FxHashMap::default();
        for op in &self.operations {
            if !matches!(op.opcode(), ECodeSsaOpcode::Constant) || op.width() <= 64 {
                continue;
            }
            if let Some(value) = op.constant(&self.constants) {
                let width_bytes = value.bits().div_ceil(8) as usize;
                let mut bytes = vec![0u8; width_bytes];
                value.to_le_bytes(&mut bytes);
                interned.insert(bytes.into_boxed_slice(), op.immediate());
            }
        }
        interned
    }
}
