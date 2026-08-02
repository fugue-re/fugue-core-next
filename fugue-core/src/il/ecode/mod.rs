pub mod ssa;

mod builder;
mod expression;
mod format;
mod operation;
mod transform;
mod verify;

pub(crate) use builder::ECodeBuilder;
pub use builder::{ECODE_SCHEMA_VERSION, ECodeIr};
pub use expression::{ECodeExpr, ECodeExprOpcode};
pub use format::{ECodeIrDisplay, ECodeSourceDisplay};
pub use operation::{ECodeStmt, ECodeStmtOpcode};
pub use transform::PCodeToECode;
