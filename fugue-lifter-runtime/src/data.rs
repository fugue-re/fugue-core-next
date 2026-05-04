use crate::constructor::Constructor;
use crate::operand::OperandFilter;
use crate::pattern::PatternOp;
use crate::resolve::DecisionNode;
use crate::symbol::Symbol;
use crate::template::{ConstTpl, ConstructTpl, HandleTpl, OpTpl, VarnodeTpl};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum SpaceKind {
    Constant,
    Default,
    Unique,
    Other,
}

pub struct SpaceInfo {
    pub name: &'static str,
    pub word_size: usize,
    pub upper_bound: u64,
    pub kind: SpaceKind,
}

pub struct LanguageData {
    pub root_dtree: u16,

    pub address_size: usize,
    pub constant_space: u8,
    pub default_space: u8,
    pub unique_space: u8,

    pub spaces: &'static [SpaceInfo],

    pub constructors: &'static [Constructor],
    pub decision_trees: &'static [DecisionNode],
    pub operand_filters: &'static [OperandFilter],
    pub pattern_expressions: &'static [PatternOp],
    pub symbols: &'static [Symbol],

    pub const_templates: &'static [ConstTpl],
    pub construct_templates: &'static [ConstructTpl],
    pub handle_templates: &'static [HandleTpl],
    pub op_templates: &'static [OpTpl],
    pub varnode_templates: &'static [VarnodeTpl],
}
