use crate::pattern::PatternExpression;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct OperandFilter {
    pub pattern: PatternExpression,
    pub indices: Box<[u16]>,
    pub limit: u16,
}
