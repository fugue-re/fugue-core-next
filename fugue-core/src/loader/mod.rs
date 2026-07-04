use std::fmt::{Debug, Display};
use std::path::Path;

use digest::Digest as _;
use fallible_iterator::FallibleIterator;
use thiserror::Error;

use crate::analysis::AnalysisError;
use crate::analysis::core::{FunctionRecovery, FunctionRecoveryConfig};
use crate::arch::Arch;
use crate::ir::Address;
use crate::ir::symbol::SymbolTable;
use crate::lifter::LanguageError;
use crate::types::{AttributeMap, BytesOrMapping};

pub mod elf;
pub use elf::Elf;

pub mod image;
pub use image::{
    ImageAddress, ImageBacking, ImageBank, ImageBankHandle, ImageLayout, ImageResolution,
    ImageSegment, ImageSegmentContents, ImageSegmentContentsIterator, ImageSegmentIterator,
    ImageSpace, ImageSpaceHandle, ImageSpaceKind, ImageWrite,
};

// pub mod macho
// pub use macho::Macho;

pub mod pe;
pub use pe::Pe;

pub mod shellcode;
pub use shellcode::Shellcode;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("cannot load object: address overflow using base address of {0}")]
    AddressOverflow(Address),
    #[error("cannot apply loader extension: {0}")]
    Extension(anyhow::Error),
    #[error("cannot load object: {0}")]
    Format(anyhow::Error),
    #[error("cannot read object: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot resolve language: {0}")]
    Language(#[from] LanguageError),
    #[error("cannot load object: {0}")]
    Other(anyhow::Error),
    #[error("cannot load object: unsupported file format")]
    UnsupportedFormat,
    #[error("cannot load object: unsupported architecture")]
    UnsupportedArch,
}

impl LoaderError {
    pub fn address_overflow(address: impl Into<Address>) -> Self {
        Self::AddressOverflow(address.into())
    }

    pub fn extension<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Extension(e.into())
    }

    pub fn extension_with<M>(m: M) -> Self
    where
        M: Debug + Display + Send + Sync + 'static,
    {
        Self::Extension(anyhow::Error::msg(m))
    }

    pub fn format<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Format(e.into())
    }

    pub fn format_with<M>(m: M) -> Self
    where
        M: Debug + Display + Send + Sync + 'static,
    {
        Self::Format(anyhow::Error::msg(m))
    }

    pub fn other<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Other(e.into())
    }

    pub fn other_with<M>(m: M) -> Self
    where
        M: Debug + Display + Send + Sync + 'static,
    {
        Self::Other(anyhow::Error::msg(m))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoadableMetadata {
    path: Option<String>, // Optional path to the loadable object
    md5: [u8; 16],        // MD5 hash of the loadable object
    sha256: [u8; 32],     // SHA-256 hash of the loadable object
    loader: String,       // The loader version string
}

impl LoadableMetadata {
    const BLOCK_SIZE: usize = 4096;

    /// Creates a new `LoadableMetadata` with the given bytes and loader.
    pub fn new(bytes: impl AsRef<[u8]>, loader: impl Into<String>) -> Self {
        Self::new_with(bytes, None, loader)
    }

    /// Creates a new `LoadableMetadata` with the given bytes, path, and loader.
    pub fn new_with(
        bytes: impl AsRef<[u8]>,
        path: impl Into<Option<String>>,
        loader: impl Into<String>,
    ) -> Self {
        let bytes = bytes.as_ref();
        let (md5, sha256) = Self::compute_hashes(bytes);

        Self {
            path: path.into(),
            md5,
            sha256,
            loader: loader.into(),
        }
    }

    /// Creates a new `LoadableMetadata` from the given MD5 and SHA-256 hashes and loader.
    pub fn from_hashes(md5: [u8; 16], sha256: [u8; 32], loader: impl Into<String>) -> Self {
        Self::from_hashes_with(md5, sha256, None, loader)
    }

    /// Creates a new `LoadableMetadata` from the given MD5 and SHA-256 hashes, path, and loader.
    pub fn from_hashes_with(
        md5: [u8; 16],
        sha256: [u8; 32],
        path: impl Into<Option<String>>,
        loader: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            md5,
            sha256,
            loader: loader.into(),
        }
    }

    fn compute_hashes(bytes: &[u8]) -> ([u8; 16], [u8; 32]) {
        let mut md5 = md5::Md5::new();
        let mut sha256 = sha2::Sha256::new();

        for chunk in bytes.chunks(Self::BLOCK_SIZE) {
            md5.update(chunk);
            sha256.update(chunk);
        }

        (md5.finalize().into(), sha256.finalize().into())
    }

    /// Returns the original path of the loadable object, if any.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Sets the path of the loadable object.
    pub fn set_path(&mut self, path: impl Into<String>) {
        self.path = Some(path.into());
    }

    /// Clears the path of the loadable object.
    pub fn clear_path(&mut self) {
        self.path = None;
    }

    /// Sets the path of the loadable object.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.set_path(path);
        self
    }

    /// Returns the MD5 hash of the loadable object.
    pub fn md5(&self) -> [u8; 16] {
        self.md5
    }

    /// Returns the SHA-256 hash of the loadable object.
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Returns the default (strongest) hash of the loadable object.
    pub fn digest(&self) -> [u8; 32] {
        self.sha256()
    }

    /// Returns the loader version string.
    pub fn loader(&self) -> &str {
        &self.loader
    }
}

pub trait LoadableFromBytes<'a>: Loadable {
    fn from_bytes(data: impl Into<BytesOrMapping<'a>>) -> Result<Self, LoaderError>
    where
        Self: Sized,
    {
        Self::from_bytes_with(data, AttributeMap::new())
    }

    fn from_bytes_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized;
}

pub trait LoadableFromFile: Loadable {
    fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, LoaderError>
    where
        Self: Sized,
    {
        Self::from_file_with(path, AttributeMap::new())
    }

    fn from_file_with(
        path: impl AsRef<std::path::Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized;
}

pub trait Loadable {
    fn attributes(&self) -> &AttributeMap;

    fn attributes_mut(&mut self) -> &mut AttributeMap;

    fn metadata(&self) -> &LoadableMetadata;

    fn architecture(&self) -> Arch;

    fn image_symbols(&self) -> Option<&SymbolTable<ImageAddress>> {
        None
    }

    fn entry_point(&self) -> Option<ImageAddress> {
        None
    }

    fn image_segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a;

    fn image_layout(&self) -> &ImageLayout;

    fn image_contents<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a;

    fn analysers(&self) -> impl LoadableAnalysers {
        DefaultLoadableAnalysers
    }
}

pub trait LoadableAnalysers {
    fn function_recovery(&self) -> Result<FunctionRecovery, AnalysisError> {
        self.function_recovery_with(FunctionRecoveryConfig::default())
    }

    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery, AnalysisError> {
        Ok(FunctionRecovery::new_with(config))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultLoadableAnalysers;

impl LoadableAnalysers for DefaultLoadableAnalysers {}

impl<T> LoadableAnalysers for Box<T>
where
    T: LoadableAnalysers + ?Sized,
{
    fn function_recovery(&self) -> Result<FunctionRecovery, AnalysisError> {
        self.as_ref().function_recovery()
    }

    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery, AnalysisError> {
        self.as_ref().function_recovery_with(config)
    }
}

impl<T> LoadableAnalysers for &T
where
    T: LoadableAnalysers + ?Sized,
{
    fn function_recovery(&self) -> Result<FunctionRecovery, AnalysisError> {
        (*self).function_recovery()
    }

    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery, AnalysisError> {
        (*self).function_recovery_with(config)
    }
}

pub enum Loader<'a> {
    Elf(elf::Elf<'a>),
    Pe(pe::Pe<'a>),
}

impl<'a> Loader<'a> {
    pub fn new(data: impl Into<BytesOrMapping<'a>>) -> Result<Self, LoaderError> {
        Self::new_with(data, AttributeMap::new())
    }

    pub fn new_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        use ::object::FileKind;

        let data = data.into();
        let loaded = match FileKind::parse(data.as_ref()).map_err(LoaderError::format)? {
            FileKind::Elf32 | FileKind::Elf64 => {
                let elf = Elf::new_with(data, attributes)?;
                Self::Elf(elf)
            }
            FileKind::Pe32 | FileKind::Pe64 => {
                let pe = Pe::new_with(data, attributes)?;
                Self::Pe(pe)
            }
            _ => return Err(LoaderError::UnsupportedFormat),
        };
        Ok(loaded)
    }

    pub fn from_file_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        let data = BytesOrMapping::from_file(path)?;
        Self::new_with(data, attributes)
    }

    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, LoaderError> {
        Self::from_file_with(path, AttributeMap::new())
    }
}

impl<'a> LoadableFromBytes<'a> for Loader<'a> {
    fn from_bytes_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        Self::new_with(data, attributes)
    }
}

impl LoadableFromFile for Loader<'_> {
    fn from_file_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized,
    {
        Self::from_file_with(path, attributes)
    }
}

impl Loadable for Loader<'_> {
    fn architecture(&self) -> Arch {
        match self {
            Self::Elf(elf) => elf.architecture(),
            Self::Pe(pe) => pe.architecture(),
        }
    }

    fn metadata(&self) -> &LoadableMetadata {
        match self {
            Self::Elf(elf) => elf.metadata(),
            Self::Pe(pe) => pe.metadata(),
        }
    }

    fn image_symbols(&self) -> Option<&SymbolTable<ImageAddress>> {
        match self {
            Self::Elf(elf) => Loadable::image_symbols(elf),
            Self::Pe(pe) => Loadable::image_symbols(pe),
        }
    }

    fn attributes(&self) -> &AttributeMap {
        match self {
            Self::Elf(elf) => elf.attributes(),
            Self::Pe(pe) => pe.attributes(),
        }
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        match self {
            Self::Elf(elf) => elf.attributes_mut(),
            Self::Pe(pe) => pe.attributes_mut(),
        }
    }

    fn entry_point(&self) -> Option<ImageAddress> {
        match self {
            Self::Elf(elf) => elf.entry_point(),
            Self::Pe(pe) => pe.entry_point(),
        }
    }

    fn image_segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a {
        let segments: ImageSegmentIterator<'a> = match self {
            Self::Elf(elf) => Box::new(elf.image_segments()),
            Self::Pe(pe) => Box::new(pe.image_segments()),
        };
        segments
    }

    fn image_layout(&self) -> &ImageLayout {
        match self {
            Self::Elf(elf) => elf.image_layout(),
            Self::Pe(pe) => pe.image_layout(),
        }
    }

    fn image_contents<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a {
        match self {
            Self::Elf(elf) => Box::new(elf.image_contents()) as ImageSegmentContentsIterator<'a>,
            Self::Pe(pe) => Box::new(pe.image_contents()) as ImageSegmentContentsIterator<'a>,
        }
    }

    fn analysers(&self) -> impl LoadableAnalysers {
        match self {
            Self::Elf(elf) => Box::new(elf.analysers()) as Box<dyn LoadableAnalysers>,
            Self::Pe(pe) => Box::new(pe.analysers()) as Box<dyn LoadableAnalysers>,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attributes;

    #[test]
    fn test_loader() -> Result<(), LoaderError> {
        let loaded = Loader::from_file_with(
            "tests/ls.elf",
            attributes![
                "test" => "test",
                "test2" => 2u32,
                "test3" => 3u64,
            ],
        )?;

        assert_eq!(loaded.architecture().language().id(), "x86:LE:64:default");
        assert_eq!(
            loaded.attributes().get_attr::<String>("test"),
            Some("test".to_owned())
        );
        assert_eq!(loaded.attributes().get_attr::<u32>("test2"), Some(2));
        assert_eq!(loaded.attributes().get_attr::<u64>("test3"), Some(3));

        assert!(!loaded.image_layout().banks().is_empty());

        Ok(())
    }
}
