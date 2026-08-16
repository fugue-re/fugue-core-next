mod builder;
mod def_use;
mod disjoint_set;
mod format;
mod ir;
mod memory;
mod opcode;
mod operation;
mod optimise;
mod recovery;
mod storage;
mod transform;
mod value;
mod variable;
mod verify;

pub use builder::{MCodeBuilder, MCodeEmitter};
pub use def_use::{MCodeBlockArgInputs, MCodeUse, MCodeUses};
pub use format::{MCodeIrDisplay, MCodeSourceDisplay};
pub use ir::MCodeIr;
pub use memory::MCodeMemoryDomain;
pub use opcode::MCodeOpcode;
pub use operation::{MCodeOp, MCodeOpSpec};
pub(crate) use optimise::MCodeOptimiser;
pub use recovery::{MCodeCallFacts, MCodeFunctionFacts, MCodeStorageFact};
pub use storage::MCodeStorageLocation;
pub use transform::ECodeToMCode;
pub use value::{MCodeBinding, MCodeBlockArg, MCodeValue, MCodeVersion};
pub use variable::{MCodeVar, MCodeVarId, MCodeVarKind};

#[cfg(test)]
mod test;
