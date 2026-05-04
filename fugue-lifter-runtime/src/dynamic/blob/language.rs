use crate::context::ContextBitRange;
use crate::dynamic::blob::constructor::Constructor;
use crate::dynamic::blob::operand::OperandFilter;
use crate::dynamic::blob::resolve::DecisionNode;
use crate::dynamic::blob::space::SpaceInfo;
use crate::dynamic::blob::symbol::Symbol;
use crate::dynamic::blob::template::{ConstructTpl, OpTpl};
use crate::pattern::PatternOp;
use crate::pcode::Varnode;
use crate::template::{ConstTpl, HandleTpl, VarnodeTpl};

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct Language {
    pub id: Box<str>,
    pub processor: Box<str>,
    pub variant: Box<str>,
    pub little_endian: bool,

    pub address_alignment: usize,
    pub address_bits: u32,
    pub address_size: usize,
    pub address_upper_bound: u64,

    pub constant_space: u8,
    pub default_space: u8,
    pub register_space: u8,
    pub register_space_size: usize,

    pub unique_mask: u64,
    pub unique_space: u8,
    pub unique_space_size: usize,

    pub root_dtree: u16,

    pub spaces: Box<[SpaceInfo]>,

    pub constructors: Box<[Constructor]>,
    pub decision_trees: Box<[DecisionNode]>,
    pub operand_filters: Box<[OperandFilter]>,
    pub pattern_expressions: Box<[PatternOp]>,
    pub symbols: Box<[Symbol]>,

    pub const_templates: Box<[ConstTpl]>,
    pub construct_templates: Box<[ConstructTpl]>,
    pub handle_templates: Box<[HandleTpl]>,
    pub op_templates: Box<[OpTpl]>,
    pub varnode_templates: Box<[VarnodeTpl]>,

    pub registers: Box<[(Box<str>, Varnode)]>,
    pub register_ranges: Box<[(u64, u16, Box<str>)]>,
    pub user_ops: Box<[Box<str>]>,
    pub context_vars: Box<[(Box<str>, ContextBitRange)]>,
    pub context_defaults: Box<[(Box<str>, u32)]>,
    pub space_names: Box<[Box<str>]>,
}
