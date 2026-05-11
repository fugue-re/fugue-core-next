use crate::template::Op;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct ConstructTpl {
    pub(crate) delay_slot: u8,
    pub(crate) labels: u8,
    pub(crate) result: Option<u16>,
    pub(crate) operations: Box<[u16]>,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct OpTpl {
    pub(crate) op: Op,
    pub(crate) inputs: Box<[u16]>,
    pub(crate) output: Option<u16>,
}
