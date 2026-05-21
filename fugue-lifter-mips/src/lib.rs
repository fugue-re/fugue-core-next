#[cfg(feature = "mips-be")]
pub mod be;
#[cfg(feature = "mips-le")]
pub mod le;

#[cfg(feature = "mips-be")]
pub use be::{context, register, space, user_op};
#[cfg(all(feature = "mips-le", not(feature = "mips-be")))]
pub use le::{context, register, space, user_op};

#[cfg(not(any(feature = "mips-be", feature = "mips-le")))]
compile_error!("At least one feature (`mips-be` or `mips-le`) must be enabled.");
