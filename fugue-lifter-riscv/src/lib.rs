#[cfg(feature = "riscv")]
pub mod riscv;
#[cfg(feature = "riscv64")]
pub mod riscv64;

#[cfg(not(any(feature = "riscv", feature = "riscv64")))]
compile_error!("At least one feature (`riscv` or `riscv64`) must be enabled.");
