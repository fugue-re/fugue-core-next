mod builder;
mod def_use;
mod domain;
mod format;
mod intervals;
mod ir;
mod liveness;
mod memory;
mod opcode;
mod operation;
mod optimise;
mod transform;
mod value;
mod verify;

pub use builder::{ECodeBuilder, ECodeEmitter};
pub use def_use::{ECodeBlockArgInputs, ECodeUse, ECodeUses};
pub use domain::ECodeDomain;
pub use format::{ECodeIrDisplay, ECodeSourceDisplay};
pub use intervals::ECodeStridedIntervals;
pub use ir::ECodeIr;
pub use liveness::ECodeLiveness;
pub use memory::ECodeMemoryDomain;
pub use opcode::ECodeOpcode;
pub use operation::{ECodeOp, ECodeOpSpec};
pub(crate) use optimise::ECodeOptimiser;
pub use transform::PCodeToECode;
pub use value::{ECodeBlockArg, ECodeValue};

#[cfg(test)]
pub(crate) mod test;
