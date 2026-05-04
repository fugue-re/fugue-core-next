#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct DecisionNode {
    pub start_bit: u32,
    pub size: u32,
    pub context_decision: bool,
    pub patterns: Box<[DecisionPair]>,
    pub children: Box<[u16]>,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct DecisionPair {
    pub constructor: u16,
    pub pattern: DisjointPattern,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum DisjointPattern {
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
pub struct Pattern {
    pub offset: usize,
    pub non_zero_size: Option<usize>,
    pub masks: Box<[u32]>,
    pub values: Box<[u32]>,
}
