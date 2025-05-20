#[cfg(feature = "aarch64-be")]
pub mod be;
#[cfg(feature = "aarch64-le")]
pub mod le;

#[cfg(feature = "aarch64-be")]
pub use be::{context, register, space, user_op};
#[cfg(all(feature = "aarch64-le", not(feature = "aarch64-be")))]
pub use le::{context, register, space, user_op};

#[cfg(not(any(feature = "aarch64-be", feature = "aarch64-le")))]
compile_error!("At least one feature (`aarch64-be` or `aarch64-le`) must be enabled.");
