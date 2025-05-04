pub mod basic_block;
pub use basic_block::BasicBlock;

pub mod function;
pub use function::Function;

pub mod instruction;
pub use instruction::{Insn, InsnProperties, InsnTarget, InsnTargetKind};

pub mod call_graph;
pub mod flow_graph;
