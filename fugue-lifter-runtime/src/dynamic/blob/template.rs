use crate::template::Op;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct ConstructTpl {
    pub delay_slot: u8,
    pub labels: u8,
    pub result: Option<u16>,
    pub operations: Box<[u16]>,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct OpTpl {
    pub op: Op,
    pub inputs: Box<[u16]>,
    pub output: Option<u16>,
}
