use crate::pattern::PatternExpression;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct OperandFilter {
    pub(crate) pattern: PatternExpression,
    pub(crate) indices: Box<[u16]>,
    pub(crate) limit: u16,
}
