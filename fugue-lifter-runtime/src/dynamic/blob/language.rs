use crate::context::ContextBitRange;
use crate::dynamic::blob::constructor::Constructor;
use crate::dynamic::blob::operand::OperandFilter;
use crate::dynamic::blob::resolve::DecisionNode;
use crate::dynamic::blob::space::AddressSpace;
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
    pub(crate) id: Box<str>,
    pub(crate) processor: Box<str>,
    pub(crate) variant: Box<str>,
    pub(crate) little_endian: bool,

    pub(crate) address_alignment: usize,
    pub(crate) address_bits: u32,
    pub(crate) address_size: usize,
    pub(crate) address_upper_bound: u64,

    pub(crate) constant_space: u8,
    pub(crate) default_space: u8,
    pub(crate) register_space: u8,
    pub(crate) register_space_size: usize,

    pub(crate) unique_mask: u64,
    pub(crate) unique_space: u8,
    pub(crate) unique_space_size: usize,

    pub(crate) root_dtree: u16,

    pub(crate) spaces: Box<[AddressSpace]>,

    pub(crate) constructors: Box<[Constructor]>,
    pub(crate) decision_trees: Box<[DecisionNode]>,
    pub(crate) operand_filters: Box<[OperandFilter]>,
    pub(crate) pattern_expressions: Box<[PatternOp]>,
    pub(crate) symbols: Box<[Symbol]>,

    pub(crate) const_templates: Box<[ConstTpl]>,
    pub(crate) construct_templates: Box<[ConstructTpl]>,
    pub(crate) handle_templates: Box<[HandleTpl]>,
    pub(crate) op_templates: Box<[OpTpl]>,
    pub(crate) varnode_templates: Box<[VarnodeTpl]>,

    pub(crate) registers: Box<[(Box<str>, Varnode)]>,
    pub(crate) register_ranges: Box<[(u64, u16, Box<str>)]>,
    pub(crate) user_ops: Box<[Box<str>]>,
    pub(crate) context_vars: Box<[(Box<str>, ContextBitRange)]>,
    pub(crate) context_defaults: Box<[(Box<str>, u32)]>,
    pub(crate) space_names: Box<[Box<str>]>,
}
