#[cfg(feature = "build")]
mod build;
#[cfg(feature = "build")]
mod spec;
#[cfg(feature = "sync")]
mod sync;
mod unpack;

#[cfg(feature = "build")]
pub use self::build::BuildError;
#[cfg(feature = "sync")]
pub use self::sync::SyncError;
pub use self::unpack::UnpackError;

#[derive(Debug, Default, Clone, Copy)]
pub struct Packager;

impl Packager {
    pub fn new() -> Self {
        Self
    }
}
