#[cfg(any(feature = "mips-be", feature = "mips-le"))]
pub mod mips;
#[cfg(any(feature = "mips64-be", feature = "mips64-le"))]
pub mod mips64;

#[cfg(feature = "mips-be")]
pub use mips::be::{context, register, space, user_op};
#[cfg(all(feature = "mips-le", not(feature = "mips-be")))]
pub use mips::le::{context, register, space, user_op};

#[cfg(not(any(
    feature = "mips-be",
    feature = "mips-le",
    feature = "mips64-be",
    feature = "mips64-le"
)))]
compile_error!(
    "At least one feature (`mips-be`, `mips-le`, `mips64-be` or `mips64-le`) must be enabled."
);
