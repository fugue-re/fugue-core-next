use crate::context::{ContextPostAction, ContextPreAction};
use crate::operand::Operand;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct Constructor {
    pub(crate) id: u16,
    pub(crate) context_pre_actions: Box<[ContextPreAction]>,
    pub(crate) context_post_actions: Box<[ContextPostAction]>,
    pub(crate) operands: Box<[Operand]>,
    pub(crate) result: Option<u16>,
    pub(crate) build_action: Option<u16>,
    pub(crate) print_pieces: Box<[PrintPiece]>,
    pub(crate) first_whitespace: Option<usize>,
    pub(crate) flow_through_index: Option<usize>,
    pub(crate) delay_slot_length: usize,
    pub(crate) minimum_length: usize,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) enum PrintPiece {
    Operand(u16),
    Token(Box<str>),
}
