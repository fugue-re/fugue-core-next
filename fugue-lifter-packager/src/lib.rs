#[cfg(feature = "bundled-compiler")]
mod build;
mod sync;
mod unpack;

#[cfg(feature = "bundled-compiler")]
pub use self::build::BuildError;
pub use self::sync::SyncError;
pub use self::unpack::UnpackError;

#[derive(Debug, Default, Clone, Copy)]
pub struct Packager;

impl Packager {
    pub fn new() -> Self {
        Self::default()
    }
}
