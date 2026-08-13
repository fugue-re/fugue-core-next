mod analysis;
mod builder;
mod error;
mod format;
mod operation;
mod register;
mod transform;
#[cfg(debug_assertions)]
mod verify;

pub(crate) use builder::PCodeBuilder;
pub use builder::PCodeIr;
pub use error::PCodeError;
pub use format::{PCodeIrDisplay, PCodeSourceDisplay};
pub use operation::{
    AddressAnnotation, AddressAnnotationRole, AddressAnnotationValue, LifterSpaceHandle,
    PCodeAddressContext, PCodeLocation, PCodeLocationId, PCodeLocationProperties, PCodeOp,
    PCodeOpcode,
};
pub use register::RegisterBank;
pub(crate) use register::RegisterSlice;
pub use transform::{PCodeCanonicaliser, PCodeFunctionInput};
