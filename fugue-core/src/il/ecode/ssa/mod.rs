mod builder;
mod constants;
pub mod def_use;
mod evaluate;
pub mod format;
mod intervals;
mod ir;
pub mod liveness;
pub mod memory;
mod opcode;
mod operation;
mod optimise;
pub mod transform;
mod value;
mod verify;

pub(crate) use builder::ECodeSsaBuilder;
pub(crate) use constants::ECodeSsaConstantInterner;
pub use def_use::{ECodeSsaBlockArgumentInputs, ECodeSsaUse, ECodeSsaUses};
pub use format::{
    ECodeSsaIrDisplay, ECodeSsaOpDisplay, ECodeSsaOpcodeDisplay, ECodeSsaValueDisplay,
};
pub use intervals::ECodeSsaStridedIntervals;
pub use ir::{ECODE_SSA_SCHEMA_VERSION, ECodeSsaIr};
pub use liveness::ECodeSsaLiveness;
pub use memory::ECodeSsaMemoryDomain;
pub use opcode::ECodeSsaOpcode;
pub use operation::ECodeSsaOp;
pub(crate) use optimise::ECodeSsaOptimiser;
pub use transform::ECodeToSsa;
pub use value::{ECodeSsaBlockArg, ECodeSsaValue, ECodeSsaValueKind};
pub(crate) use verify::verify;

#[cfg(test)]
mod test;
