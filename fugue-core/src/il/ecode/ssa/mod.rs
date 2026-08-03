mod builder;
mod constants;
mod def_use;
mod evaluate;
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

pub(crate) use builder::ECodeSsaBuilder;
pub(crate) use constants::ECodeSsaConstantInterner;
pub use def_use::{ECodeSsaBlockArgumentInputs, ECodeSsaUse, ECodeSsaUses};
pub use format::{ECodeSsaIrDisplay, ECodeSsaSourceDisplay};
pub use intervals::ECodeSsaStridedIntervals;
pub use ir::ECodeSsaIr;
pub(crate) use ir::ECodeSsaIrParts;
pub use liveness::ECodeSsaLiveness;
pub use memory::ECodeSsaMemoryDomain;
pub use opcode::ECodeSsaOpcode;
pub use operation::ECodeSsaOp;
pub(crate) use optimise::ECodeSsaOptimiser;
pub use transform::ECodeToSsa;
pub use value::{ECodeSsaBlockArg, ECodeSsaValue, ECodeSsaValueKind};

#[cfg(test)]
mod test;
