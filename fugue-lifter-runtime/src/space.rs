#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum AddressSpaceKind {
    Constant,
    Default,
    Unique,
    Other,
}

pub struct AddressSpace {
    name: &'static str,
    word_size: usize,
    upper_bound: u64,
    kind: AddressSpaceKind,
}

impl AddressSpace {
    pub const fn new(
        name: &'static str,
        word_size: usize,
        upper_bound: u64,
        kind: AddressSpaceKind,
    ) -> Self {
        Self {
            name,
            word_size,
            upper_bound,
            kind,
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn word_size(&self) -> usize {
        self.word_size
    }

    pub fn upper_bound(&self) -> u64 {
        self.upper_bound
    }

    pub fn kind(&self) -> AddressSpaceKind {
        self.kind
    }
}
