#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct Revision(u64);

impl Revision {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0
    }

    pub const fn next(&self) -> Self {
        let next = self.0.checked_add(1).expect("revision should not overflow");
        Self(next)
    }
}

impl From<u64> for Revision {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}
