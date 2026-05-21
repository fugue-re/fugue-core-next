#[cfg(all(feature = "dynamic", any(feature = "bundled", feature = "compiled")))]
compile_error!("`dynamic` is mutually exclusive with `bundled` and `compiled`");

#[cfg(any(feature = "aarch64-be", feature = "aarch64-le"))]
pub use fugue_lifter_aarch64 as aarch64;
#[cfg(any(feature = "arm-be", feature = "arm-le"))]
pub use fugue_lifter_arm as arm;
#[cfg(any(feature = "mips-be", feature = "mips-le"))]
pub use fugue_lifter_mips as mips;
#[cfg(feature = "x86")]
pub use fugue_lifter_x86::x86;
#[cfg(feature = "x86-64")]
pub use fugue_lifter_x86::x86_64;

pub mod builder;
pub use builder::{LifterBuilder, LifterBuilderError};
pub use fugue_lifter_runtime as runtime;
#[cfg(feature = "dynamic")]
pub use fugue_lifter_runtime::dynamic;
#[cfg(feature = "dynamic")]
pub use fugue_lifter_runtime::dynamic::LanguageLoadError;
pub use runtime::context::ContextBitRange;
pub use runtime::language::{Language, LanguageId, LanguageVariant};
pub use runtime::lifter::Lifter;
pub use runtime::pcode::{
    LiftingContext, LiftingContextState, Op, PCodeBuilder, PCodeBuilderContext, PCodeOp, Varnode,
};
