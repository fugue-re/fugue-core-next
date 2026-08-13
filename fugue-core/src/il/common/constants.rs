use fugue_bv::BitVec;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

#[derive(Debug)]
pub(crate) struct IlConstantInterner {
    offsets: FxHashMap<Box<[u8]>, u64>,
    scratch: SmallVec<[u8; 16]>,
}

impl IlConstantInterner {
    pub(crate) fn new() -> Self {
        Self {
            offsets: FxHashMap::default(),
            scratch: SmallVec::new(),
        }
    }

    pub(crate) fn index_existing(&mut self, bytes: &[u8], offset: u64) {
        if !self.offsets.contains_key(bytes) {
            self.offsets.insert(Box::<[u8]>::from(bytes), offset);
        }
    }

    pub(crate) fn intern(&mut self, storage: &mut Vec<u8>, value: &BitVec) -> u64 {
        let width_bytes = value.bits().div_ceil(8) as usize;
        if value.bits() <= 64 {
            let mut inline = [0u8; 8];
            value.to_le_bytes(&mut inline[..width_bytes]);
            return u64::from_le_bytes(inline);
        }

        self.scratch.resize(width_bytes, 0);
        value.to_le_bytes(&mut self.scratch);
        if let Some(&offset) = self.offsets.get(self.scratch.as_slice()) {
            return offset;
        }
        let offset = storage.len() as u64;
        storage.extend_from_slice(&self.scratch);
        self.offsets
            .insert(Box::from(self.scratch.as_slice()), offset);
        offset
    }
}
