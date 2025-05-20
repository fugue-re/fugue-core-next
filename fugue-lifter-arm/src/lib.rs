#[cfg(feature = "arm-be")]
pub mod be;
#[cfg(feature = "arm-le")]
pub mod le;

#[cfg(feature = "arm-be")]
pub use be::{context, register, space, user_op};
#[cfg(all(feature = "arm-le", not(feature = "arm-be")))]
pub use le::{context, register, space, user_op};

#[cfg(not(any(feature = "arm-be", feature = "arm-le")))]
compile_error!("At least one feature (`arm-be` or `arm-le`) must be enabled.");
