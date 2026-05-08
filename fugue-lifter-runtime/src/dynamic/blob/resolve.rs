#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct DecisionNode {
    pub(crate) start_bit: u32,
    pub(crate) size: u32,
    pub(crate) context_decision: bool,
    pub(crate) patterns: Box<[DecisionPair]>,
    pub(crate) children: Box<[u16]>,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct DecisionPair {
    pub(crate) constructor: u16,
    pub(crate) pattern: DisjointPattern,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) enum DisjointPattern {
    Context(Pattern),
    Instruction(Pattern),
    Combine {
        context: Pattern,
        instruction: Pattern,
    },
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct Pattern {
    pub(crate) offset: usize,
    pub(crate) non_zero_size: Option<usize>,
    pub(crate) masks: Box<[u32]>,
    pub(crate) values: Box<[u32]>,
}
