#[cfg(any(feature = "ppc-be", feature = "ppc-le"))]
pub mod ppc;
#[cfg(any(
    feature = "ppc64-a2alt-be",
    feature = "ppc64-a2alt-le",
    feature = "ppc64-be",
    feature = "ppc64-le"
))]
pub mod ppc64;

#[cfg(not(any(
    feature = "ppc-be",
    feature = "ppc-le",
    feature = "ppc64-a2alt-be",
    feature = "ppc64-a2alt-le",
    feature = "ppc64-be",
    feature = "ppc64-le"
)))]
compile_error!(
    "At least one feature (`ppc-be`, `ppc-le`, `ppc64-be`, `ppc64-le`, `ppc64-a2alt-be` or `ppc64-a2alt-le`) must be enabled."
);
