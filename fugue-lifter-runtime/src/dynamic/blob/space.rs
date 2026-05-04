use crate::data::SpaceKind;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct SpaceInfo {
    pub name: Box<str>,
    pub word_size: usize,
    pub upper_bound: u64,
    pub kind: SpaceKind,
}
