use fugue_bv::BitVec;
use rustc_hash::FxHashMap;

use crate::il::ecode::ssa::{ECodeSsaOp, ECodeSsaOpcode};

pub(crate) struct ECodeSsaConstantInterner<'a> {
    storage: &'a mut Vec<u8>,
    offsets: FxHashMap<Box<[u8]>, u64>,
    scratch: Vec<u8>,
}

impl<'a> ECodeSsaConstantInterner<'a> {
    pub(crate) fn new(storage: &'a mut Vec<u8>) -> Self {
        Self {
            storage,
            offsets: FxHashMap::default(),
            scratch: Vec::new(),
        }
    }

    pub(crate) fn seed(&mut self, operations: &[ECodeSsaOp]) {
        for operation in operations {
            if !matches!(operation.opcode(), ECodeSsaOpcode::Constant) || operation.width() <= 64 {
                continue;
            }
            if let Some(value) = operation.constant(self.storage) {
                self.write_bytes(&value);
                if !self.offsets.contains_key(self.scratch.as_slice()) {
                    self.offsets.insert(
                        self.scratch.clone().into_boxed_slice(),
                        operation.immediate(),
                    );
                }
            }
        }
    }

    pub(crate) fn intern(&mut self, value: &BitVec) -> u64 {
        let width_bytes = value.bits().div_ceil(8) as usize;
        if value.bits() <= 64 {
            let mut inline = [0u8; 8];
            value.to_le_bytes(&mut inline[..width_bytes]);
            return u64::from_le_bytes(inline);
        }

        self.write_bytes(value);
        if let Some(&offset) = self.offsets.get(self.scratch.as_slice()) {
            return offset;
        }
        let offset = self.storage.len() as u64;
        self.storage.extend_from_slice(&self.scratch);
        self.offsets
            .insert(self.scratch.clone().into_boxed_slice(), offset);
        offset
    }

    fn write_bytes(&mut self, value: &BitVec) {
        self.scratch.resize(value.bits().div_ceil(8) as usize, 0);
        value.to_le_bytes(&mut self.scratch);
    }
}
