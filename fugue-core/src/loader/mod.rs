use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display};
use std::ops::{Range, RangeInclusive};
use std::path::Path;

use bincode::{Decode, Encode};
use digest::Digest as _;
use fallible_iterator::FallibleIterator;

use fugue_bytes::traits::ByteCast;
use fugue_bytes::{BE, LE};

use thiserror::Error;

use crate::arch::Arch;
use crate::ir::symbol::IndexedSymbolTable;
use crate::ir::{Address, SegmentProperties};
use crate::lifter::ContextHint;
use crate::types::{AttributeMap, BytesOrMapping};

pub mod elf;
pub use elf::Elf;

// pub mod macho
// pub use macho::Macho;

pub mod object;
pub use object::Object;

// pub mod pe;
// pub use pe::{Pe, Te};

pub mod shellcode;
pub use shellcode::Shellcode;

pub mod util;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("cannot load object: {0}")]
    Format(anyhow::Error),
    #[error("cannot read object: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot load object: {0}")]
    Other(anyhow::Error),
    #[error("cannot load object; unsupported architecture")]
    UnsupportedArch,
}

impl LoaderError {
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct LoadableSegment<'a> {
    name: Cow<'a, str>,                                     // Name of the segment
    address: Address,                                       // Starting address of the segment
    properties: SegmentProperties, // Properties of the segment (e.g., permissions)
    bytes: Cow<'a, [u8]>,          // Bytes of the segment
    mapping_hints: Cow<'a, BTreeMap<Address, ContextHint>>, // Mapping hints for ranges within the segment
    function_hints: Cow<'a, BTreeSet<Address>>, // Hints for function start addresses within the segment
}

impl Display for LoadableSegment<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} with bounds {}-{} and properties {:?}; at least {} potential functions",
            self.name,
            self.address,
            self.last_address(),
            self.properties,
            self.function_hints.len(),
        )
    }
}

impl<'a> LoadableSegment<'a> {
    /// Creates a new `LoadableSegment` with the given name, address, properties, and bytes.
    pub fn new(
        name: impl Into<Cow<'a, str>>,
        address: Address,
        properties: SegmentProperties,
        bytes: impl Into<Cow<'a, [u8]>>,
    ) -> LoadableSegment<'a> {
        Self::from_parts(
            name,
            address,
            properties,
            bytes,
            Cow::Owned(BTreeMap::new()),
            Cow::Owned(BTreeSet::new()),
        )
    }

    /// Creates a new `LoadableSegment` with the given name, address, properties, bytes, and hints.
    pub fn new_with_hints(
        name: impl Into<Cow<'a, str>>,
        address: Address,
        properties: SegmentProperties,
        bytes: impl Into<Cow<'a, [u8]>>,
        mapping_hints: impl Into<Cow<'a, BTreeMap<Address, ContextHint>>>,
        function_hints: impl Into<Cow<'a, BTreeSet<Address>>>,
    ) -> LoadableSegment<'a> {
        Self::from_parts(
            name,
            address,
            properties,
            bytes,
            mapping_hints,
            function_hints,
        )
    }

    /// Creates a new `LoadableSegment` with the given name, address, properties, and bytes, and
    /// hints.
    pub fn from_parts(
        name: impl Into<Cow<'a, str>>,
        address: Address,
        properties: SegmentProperties,
        bytes: impl Into<Cow<'a, [u8]>>,
        mapping_hints: impl Into<Cow<'a, BTreeMap<Address, ContextHint>>>,
        function_hints: impl Into<Cow<'a, BTreeSet<Address>>>,
    ) -> LoadableSegment<'a> {
        Self {
            name: name.into(),
            address,
            properties,
            bytes: bytes.into(),
            mapping_hints: mapping_hints.into(),
            function_hints: function_hints.into(),
        }
    }

    /// Returns the address of the segment.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the next address after the segment.
    pub fn next_address(&self) -> Address {
        self.address + self.bytes.len()
    }

    /// Returns the last address of the segment.
    pub fn last_address(&self) -> Address {
        self.address + self.bytes.len() - 1usize
    }

    /// Returns the name of the segment.
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// Returns the properties of the segment.
    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    /// Returns the bytes of the segment.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the context hints of the segment.
    pub fn mapping_hints(&self) -> &BTreeMap<Address, ContextHint> {
        &self.mapping_hints
    }

    /// Returns a mutable reference to the context hints of the segment.
    pub fn mapping_hints_mut(&mut self) -> &mut BTreeMap<Address, ContextHint> {
        self.mapping_hints.to_mut()
    }

    // Adds a context hint to the segment.
    pub fn add_context_hint(&mut self, address: impl Into<Address>, hint: ContextHint) {
        self.mapping_hints.to_mut().insert(address.into(), hint);
    }

    /// Returns the function hints of the segment.
    pub fn function_hints(&self) -> &BTreeSet<Address> {
        &self.function_hints
    }

    /// Returns a mutable reference to the function hints of the segment.
    pub fn function_hints_mut(&mut self) -> &mut BTreeSet<Address> {
        self.function_hints.to_mut()
    }

    /// Adds a function hint to the segment.
    pub fn add_function_hint(&mut self, address: impl Into<Address>) {
        self.function_hints.to_mut().insert(address.into());
    }

    /// Returns the length of the segment in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the segment is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the offset of the given address within the segment, if it is contained within the
    /// segment.
    pub fn offset_of(&self, address: Address) -> Option<usize> {
        if address < self.address || address > self.last_address() {
            return None;
        }
        Some(usize::from(address - self.address))
    }

    /// Checks if the segment contains the given address.
    pub fn contains_address(&self, address: Address) -> bool {
        address >= self.address && address <= self.last_address()
    }

    /// Returns the value at the given offset, if the offset is valid.
    pub fn read_value<T: ByteCast>(&self, offset: usize) -> Option<T> {
        let range = self.view_bytes_at(offset, T::SIZEOF)?;
        Some(if self.properties.is_little_endian() {
            T::from_bytes::<LE>(range)
        } else {
            T::from_bytes::<BE>(range)
        })
    }

    /// Updates the value at the given offset using the provided function, if the offset is valid.
    pub fn update_value<T: ByteCast>(
        &mut self,
        offset: usize,
        f: impl FnOnce(T) -> T,
    ) -> Option<()> {
        let is_le = self.properties.is_little_endian();
        let range = self.view_bytes_at_mut(offset, T::SIZEOF)?;
        Some(if is_le {
            f(T::from_bytes::<LE>(range)).into_bytes::<LE>(range)
        } else {
            f(T::from_bytes::<BE>(range)).into_bytes::<BE>(range)
        })
    }

    /// Writes the value at the given offset, if the offset is valid.
    pub fn write_value<T: ByteCast>(&mut self, offset: usize, value: T) -> Option<()> {
        let is_le = self.properties.is_little_endian();
        let range = self.view_bytes_at_mut(offset, T::SIZEOF)?;

        Some(if is_le {
            value.into_bytes::<LE>(range)
        } else {
            value.into_bytes::<BE>(range)
        })
    }

    /// Returns a view of the segment's bytes from the given offset, if the offset and count
    /// correspond to a valid range.
    pub fn view_bytes_at(&self, offset: usize, count: usize) -> Option<&[u8]> {
        let len = self.bytes.len();
        if offset >= len {
            return None;
        }

        if let Some(last_offset) = offset.checked_add(count) {
            if last_offset > len {
                None
            } else {
                Some(&self.bytes[offset..last_offset])
            }
        } else {
            None
        }
    }

    /// Returns a view of the segment's bytes at the given address, if the address and count
    /// correspond to a valid range.
    pub fn view_bytes_at_address(&self, address: Address, count: usize) -> Option<&[u8]> {
        let offset = self.offset_of(address)?;
        self.view_bytes_at(offset, count)
    }

    /// Returns a view of the segment's bytes from the given offset, if the offset is valid.
    pub fn view_bytes_from(&self, offset: usize) -> Option<&[u8]> {
        let len = self.bytes.len();
        if offset >= len {
            return None;
        }

        Some(&self.bytes[offset..])
    }

    /// Returns a view of the segment's bytes from the given address, if the address is valid.
    pub fn view_bytes_from_address(&self, address: Address) -> Option<&[u8]> {
        let offset = self.offset_of(address)?;
        self.view_bytes_from(offset)
    }

    /// Returns a mutable view of the segment's bytes at the given offset, if the offset and count
    /// correspond to a valid range.
    pub fn view_bytes_at_mut(&mut self, offset: usize, count: usize) -> Option<&mut [u8]> {
        let len = self.bytes.len();
        if offset >= len {
            return None;
        }

        if let Some(last_offset) = offset.checked_add(count) {
            if last_offset > len {
                None
            } else {
                Some(&mut self.bytes.to_mut()[offset..last_offset])
            }
        } else {
            None
        }
    }

    /// Returns a mutable view of the segment's bytes at the given address, if the address and
    /// count correspond to a valid range.
    pub fn view_bytes_at_address_mut(
        &mut self,
        address: Address,
        count: usize,
    ) -> Option<&mut [u8]> {
        let offset = self.offset_of(address)?;
        self.view_bytes_at_mut(offset, count)
    }

    /// Returns a mutable view of the segment's bytes from the given offset, if the offset is
    /// valid.
    pub fn view_bytes_from_mut(&mut self, offset: usize) -> Option<&mut [u8]> {
        let len = self.bytes.len();
        if offset >= len {
            return None;
        }

        Some(&mut self.bytes.to_mut()[offset..])
    }

    /// Returns a mutable view of the segment's bytes from the given address, if the address is
    /// valid.
    pub fn view_bytes_from_address_mut(&mut self, address: Address) -> Option<&mut [u8]> {
        let offset = self.offset_of(address)?;
        self.view_bytes_from_mut(offset)
    }

    pub fn into_owned(self) -> LoadableSegment<'static> {
        LoadableSegment {
            name: self.name.into_owned().into(),
            address: self.address,
            properties: self.properties,
            bytes: self.bytes.into_owned().into(),
            mapping_hints: Cow::Owned(self.mapping_hints.into_owned()),
            function_hints: Cow::Owned(self.function_hints.into_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct LoadableSegmentMetadata {
    name: String,
    address: Address,
    physical_offset: Option<usize>,
    properties: SegmentProperties,
    size: usize,
    mapping_hints: BTreeMap<Address, ContextHint>,
    function_hints: BTreeSet<Address>,
}

impl LoadableSegmentMetadata {
    pub fn new(segm: &LoadableSegment, physical_offset: impl Into<Option<usize>>) -> Self {
        Self {
            address: segm.address(),
            name: segm.name().to_owned(),
            physical_offset: physical_offset.into(),
            properties: segm.properties(),
            size: segm.len(),
            mapping_hints: segm.mapping_hints().clone(),
            function_hints: segm.function_hints().clone(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn last_address(&self) -> Address {
        self.address + self.size as u64 - 1usize
    }

    pub fn next_address(&self) -> Address {
        self.address + self.size
    }

    pub fn range(&self) -> Range<Address> {
        self.address()..self.next_address()
    }

    pub fn range_inclusive(&self) -> RangeInclusive<Address> {
        self.address()..=self.last_address()
    }

    pub fn physical_offset(&self) -> Option<usize> {
        self.physical_offset
    }

    pub fn physical_range(&self) -> Option<Range<usize>> {
        self.physical_offset
            .map(|offset| offset..offset + self.size)
    }

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    pub fn mapping_hints(&self) -> &BTreeMap<Address, ContextHint> {
        &self.mapping_hints
    }

    pub fn function_hints(&self) -> &BTreeSet<Address> {
        &self.function_hints
    }

    pub fn len(&self) -> usize {
        self.size
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

    fn symbols(&self) -> Option<&IndexedSymbolTable> {
        None
    }

    fn segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = LoadableSegment<'a>, Error = LoaderError> + 'a;

    fn segment_range(&self) -> (Address, Address);
}

pub enum Loader<'a> {
    Elf(elf::Elf<'a>),
    Object(object::Object<'a>),
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
            _ => {
                let object = object::Object::new_with(data, attributes)?;
                Self::Object(object)
            }
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
            Self::Object(object) => object.architecture(),
        }
    }

    fn metadata(&self) -> &LoadableMetadata {
        match self {
            Self::Elf(elf) => elf.metadata(),
            Self::Object(object) => object.metadata(),
        }
    }

    fn symbols(&self) -> Option<&IndexedSymbolTable> {
        match self {
            Self::Elf(elf) => Some(elf.symbols()),
            Self::Object(object) => object.symbols(),
        }
    }

    fn attributes(&self) -> &AttributeMap {
        match self {
            Self::Elf(elf) => elf.attributes(),
            Self::Object(object) => object.attributes(),
        }
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        match self {
            Self::Elf(elf) => elf.attributes_mut(),
            Self::Object(object) => object.attributes_mut(),
        }
    }

    fn segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = LoadableSegment<'a>, Error = LoaderError> + 'a {
        match self {
            Self::Elf(elf) => {
                Box::new(elf.segments()) as Box<dyn FallibleIterator<Item = _, Error = _>>
            }
            Self::Object(object) => {
                Box::new(object.segments()) as Box<dyn FallibleIterator<Item = _, Error = _>>
            }
        }
    }

    fn segment_range(&self) -> (Address, Address) {
        match self {
            Self::Elf(elf) => elf.segment_range(),
            Self::Object(object) => object.segment_range(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::attributes;

    use super::*;

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

        let (start, end) = loaded.segment_range();

        println!("segment range: {start:#x} - {end:#x}");

        Ok(())
    }
}
