use crate::space::AddressSpaceKind;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct AddressSpace {
    pub(crate) name: Box<str>,
    pub(crate) word_size: usize,
    pub(crate) upper_bound: u64,
    pub(crate) kind: AddressSpaceKind,
}
