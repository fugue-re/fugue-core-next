pub mod ssa;

mod disjoint_set;
mod recovery;
mod transform;
mod variable;

pub use recovery::MCodeStorageLocation;
pub use transform::ECodeSsaToMCode;
pub use variable::{MCodeVar, MCodeVarId, MCodeVarKind};
