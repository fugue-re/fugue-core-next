use crate::context::{ContextPostAction, ContextPreAction};
use crate::operand::Operand;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct Constructor {
    pub id: u16,
    pub context_pre_actions: Box<[ContextPreAction]>,
    pub context_post_actions: Box<[ContextPostAction]>,
    pub operands: Box<[Operand]>,
    pub result: Option<u16>,
    pub build_action: Option<u16>,
    pub print_pieces: Box<[PrintPiece]>,
    pub first_whitespace: Option<usize>,
    pub flow_through_index: Option<usize>,
    pub delay_slot_length: usize,
    pub minimum_length: usize,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum PrintPiece {
    Operand(u16),
    Token(Box<str>),
}
