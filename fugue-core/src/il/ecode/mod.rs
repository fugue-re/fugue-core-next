pub mod ssa;

mod builder;
mod expression;
mod format;
mod lift;
mod operation;
mod sink;
mod transform;
mod verify;

pub(crate) use builder::ECodeBuilder;
pub use builder::ECodeIr;
pub use expression::{ECodeExpr, ECodeExprOpcode};
pub use format::{ECodeIrDisplay, ECodeSourceDisplay};
pub(crate) use lift::{ECodeLiftScratch, ECodeLifter};
pub use operation::{ECodeStmt, ECodeStmtOpcode};
pub(crate) use sink::ECodeSink;
pub use transform::PCodeToECode;
