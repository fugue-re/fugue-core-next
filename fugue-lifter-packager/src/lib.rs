#[cfg(feature = "build")]
mod build;
#[cfg(feature = "build")]
mod spec;
#[cfg(feature = "sync")]
mod sync;
mod unpack;

#[cfg(feature = "build")]
pub use build::BuildError;
#[cfg(feature = "sync")]
pub use sync::SyncError;
pub use unpack::UnpackError;

#[derive(Debug, Default, Clone, Copy)]
pub struct Packager;

impl Packager {
    pub fn new() -> Self {
        Self
    }
}
