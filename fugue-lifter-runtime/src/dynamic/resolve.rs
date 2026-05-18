use fugue_sleigh_language::symbol::sub_table::{
    DecisionPair as SleighDecisionPair, DisjointPattern as SleighDisjointPattern,
    PatternBlock as SleighPatternBlock,
};

use crate::dynamic::install::Install;
use crate::dynamic::tables::Tables;

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

impl Install for DecisionNode {
    type Target = crate::resolve::DecisionNode;

    fn install(self) -> Self::Target {
        let Self {
            start_bit,
            size,
            context_decision,
            patterns,
            children,
        } = self;
        Self::Target {
            start_bit,
            size,
            context_decision,
            patterns: patterns.install(),
            children: children.install(),
        }
    }
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

impl DecisionPair {
    pub(crate) fn from_sleigh(
        tables: &Tables<'_>,
        id: usize,
        scope: usize,
        pair: &SleighDecisionPair,
    ) -> Self {
        let constructor = u16::try_from(tables.ctor_for(id, scope, pair.id()))
            .expect("constructor id fits in u16");
        let pattern = DisjointPattern::from_sleigh(pair.pattern());
        Self {
            constructor,
            pattern,
        }
    }
}

impl Install for DecisionPair {
    type Target = crate::resolve::DecisionPair;

    fn install(self) -> Self::Target {
        let Self {
            constructor,
            pattern,
        } = self;
        Self::Target {
            constructor,
            pattern: pattern.install(),
        }
    }
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

impl DisjointPattern {
    pub(crate) fn from_sleigh(pattern: &SleighDisjointPattern) -> Self {
        match pattern {
            SleighDisjointPattern::Instruction(p) => {
                Self::Instruction(Pattern::from_sleigh(p.mask_value()))
            }
            SleighDisjointPattern::Context(p) => {
                Self::Context(Pattern::from_sleigh(p.mask_value()))
            }
            SleighDisjointPattern::Combine {
                context,
                instruction,
            } => Self::Combine {
                context: Pattern::from_sleigh(context.mask_value()),
                instruction: Pattern::from_sleigh(instruction.mask_value()),
            },
        }
    }
}

impl Install for DisjointPattern {
    type Target = crate::resolve::DisjointPattern;

    fn install(self) -> Self::Target {
        match self {
            Self::Context(pat) => Self::Target::Context(pat.install()),
            Self::Instruction(pat) => Self::Target::Instruction(pat.install()),
            Self::Combine {
                context,
                instruction,
            } => Self::Target::Combine {
                context: context.install(),
                instruction: instruction.install(),
            },
        }
    }
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

impl Pattern {
    pub(crate) fn from_sleigh(pattern: &SleighPatternBlock) -> Self {
        Self {
            offset: pattern.offset(),
            non_zero_size: pattern.non_zero_size(),
            masks: pattern.masks().to_vec().into_boxed_slice(),
            values: pattern.values().to_vec().into_boxed_slice(),
        }
    }
}

impl Install for Pattern {
    type Target = crate::resolve::Pattern;

    fn install(self) -> Self::Target {
        let Self {
            offset,
            non_zero_size,
            masks,
            values,
        } = self;
        Self::Target {
            offset,
            non_zero_size,
            masks: masks.install(),
            values: values.install(),
        }
    }
}
