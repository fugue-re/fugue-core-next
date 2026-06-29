use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::{Add, Range};

use fallible_iterator::FallibleIterator;
use fugue_bytes::{BE, ByteCast, LE};
use smallvec::{SmallVec, smallvec};

use crate::ir::{Address, RawAddress, SegmentProperties};
use crate::lifter::ContextHint;
use crate::loader::LoaderError;
use crate::storage::segments::SegmentStorageProviderId;
use crate::storage::segments::mapping::SegmentMappingProvenance;
use crate::storage::segments::space::AddressSpaceId;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct ImageBankHandle(u16);

impl ImageBankHandle {
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(&self) -> usize {
        self.0 as usize
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct ImageSpaceHandle(u16);

impl ImageSpaceHandle {
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(&self) -> usize {
        self.0 as usize
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct ImageAddress {
    space: ImageSpaceHandle,
    offset: RawAddress,
}

impl ImageAddress {
    pub fn new(space: ImageSpaceHandle, offset: impl Into<RawAddress>) -> Self {
        Self {
            space,
            offset: offset.into(),
        }
    }

    pub fn in_default_space(offset: impl Into<RawAddress>) -> Self {
        Self::new(ImageSpaceHandle::default(), offset)
    }

    pub fn space(&self) -> ImageSpaceHandle {
        self.space
    }

    pub fn offset(&self) -> RawAddress {
        self.offset
    }
}

impl fmt::Display for ImageAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.space.index(), self.offset)
    }
}

impl fmt::LowerHex for ImageAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.space.index())?;
        fmt::LowerHex::fmt(&self.offset, f)
    }
}

impl Add<usize> for ImageAddress {
    type Output = Self;

    fn add(self, rhs: usize) -> Self {
        Self::new(self.space, self.offset + rhs)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(derive(PartialEq, Eq, Hash))]
pub enum ImageSpaceKind {
    Base { bank: ImageBankHandle },
    Overlay { base: ImageSpaceHandle },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageBank {
    handle: ImageBankHandle,
    range: Range<RawAddress>,
}

impl ImageBank {
    pub fn new(handle: ImageBankHandle, range: Range<RawAddress>) -> Self {
        Self { handle, range }
    }

    pub fn handle(&self) -> ImageBankHandle {
        self.handle
    }

    pub fn range(&self) -> &Range<RawAddress> {
        &self.range
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSpace {
    handle: ImageSpaceHandle,
    kind: ImageSpaceKind,
}

impl ImageSpace {
    pub fn new(handle: ImageSpaceHandle, kind: ImageSpaceKind) -> Self {
        Self { handle, kind }
    }

    pub fn base(handle: ImageSpaceHandle, bank: ImageBankHandle) -> Self {
        Self::new(handle, ImageSpaceKind::Base { bank })
    }

    pub fn overlay(handle: ImageSpaceHandle, base: ImageSpaceHandle) -> Self {
        Self::new(handle, ImageSpaceKind::Overlay { base })
    }

    pub fn handle(&self) -> ImageSpaceHandle {
        self.handle
    }

    pub fn kind(&self) -> ImageSpaceKind {
        self.kind
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageLayout {
    banks: SmallVec<[ImageBank; 4]>,
    spaces: SmallVec<[ImageSpace; 4]>,
}

impl ImageLayout {
    pub fn new(
        banks: impl Into<SmallVec<[ImageBank; 4]>>,
        spaces: impl Into<SmallVec<[ImageSpace; 4]>>,
    ) -> Self {
        Self {
            banks: banks.into(),
            spaces: spaces.into(),
        }
    }

    pub fn single_bank(size: u64) -> Self {
        let bank = ImageBankHandle::default();
        let space = ImageSpaceHandle::default();
        Self::new(
            smallvec![ImageBank::new(bank, RawAddress::zero()..size.into())],
            smallvec![ImageSpace::base(space, bank)],
        )
    }

    pub fn banks(&self) -> &[ImageBank] {
        &self.banks
    }

    pub fn spaces(&self) -> &[ImageSpace] {
        &self.spaces
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(derive(PartialEq, Eq, Hash))]
pub struct ImageBacking {
    bank: ImageBankHandle,
    offset: RawAddress,
}

impl ImageBacking {
    pub fn new(bank: ImageBankHandle, offset: impl Into<RawAddress>) -> Self {
        Self {
            bank,
            offset: offset.into(),
        }
    }

    pub fn in_default_bank(offset: impl Into<RawAddress>) -> Self {
        Self::new(ImageBankHandle::default(), offset)
    }

    pub fn bank(&self) -> ImageBankHandle {
        self.bank
    }

    pub fn offset(&self) -> RawAddress {
        self.offset
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageWrite<'a> {
    bank: ImageBankHandle,
    bytes: Cow<'a, [u8]>,
    offset: RawAddress,
}

impl<'a> ImageWrite<'a> {
    pub fn new(
        bank: ImageBankHandle,
        offset: impl Into<RawAddress>,
        bytes: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        Self {
            bank,
            bytes: bytes.into(),
            offset: offset.into(),
        }
    }

    pub fn bank(&self) -> ImageBankHandle {
        self.bank
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn offset(&self) -> RawAddress {
        self.offset
    }

    pub fn into_owned(self) -> ImageWrite<'static> {
        ImageWrite {
            bank: self.bank,
            bytes: Cow::Owned(self.bytes.into_owned()),
            offset: self.offset,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSegment<'a> {
    address: ImageAddress,
    backing: Option<ImageBacking>,
    function_hints: Cow<'a, BTreeSet<RawAddress>>,
    mapping_hints: Cow<'a, BTreeMap<RawAddress, ContextHint>>,
    name: Cow<'a, str>,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
    size: usize,
}

impl<'a> ImageSegment<'a> {
    pub fn new(
        name: impl Into<Cow<'a, str>>,
        address: ImageAddress,
        size: usize,
        properties: SegmentProperties,
    ) -> Self {
        Self {
            address,
            backing: None,
            function_hints: Cow::Owned(BTreeSet::new()),
            mapping_hints: Cow::Owned(BTreeMap::new()),
            name: name.into(),
            properties,
            provenance: SegmentMappingProvenance::default(),
            size,
        }
    }

    pub fn backed_in_default_bank(
        name: impl Into<Cow<'a, str>>,
        address: ImageAddress,
        size: usize,
        properties: SegmentProperties,
        provenance: impl Into<SegmentMappingProvenance>,
        bank_base: RawAddress,
    ) -> Self {
        Self::new(name, address, size, properties)
            .with_backing(ImageBacking::in_default_bank(address.offset() - bank_base))
            .with_provenance(provenance)
    }

    pub fn address(&self) -> ImageAddress {
        self.address
    }

    pub fn backing(&self) -> Option<ImageBacking> {
        self.backing
    }

    pub fn function_hints(&self) -> &BTreeSet<RawAddress> {
        &self.function_hints
    }

    pub fn mapping_hints(&self) -> &BTreeMap<RawAddress, ContextHint> {
        &self.mapping_hints
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    pub fn provenance(&self) -> SegmentMappingProvenance {
        self.provenance
    }

    pub fn set_backing(&mut self, backing: impl Into<Option<ImageBacking>>) {
        self.backing = backing.into();
    }

    pub fn set_function_hints(&mut self, function_hints: impl Into<Cow<'a, BTreeSet<RawAddress>>>) {
        self.function_hints = function_hints.into();
    }

    pub fn set_mapping_hints(
        &mut self,
        mapping_hints: impl Into<Cow<'a, BTreeMap<RawAddress, ContextHint>>>,
    ) {
        self.mapping_hints = mapping_hints.into();
    }

    pub fn set_provenance(&mut self, provenance: impl Into<SegmentMappingProvenance>) {
        self.provenance = provenance.into();
    }

    pub fn size(&self) -> usize {
        self.size
    }

    #[allow(clippy::type_complexity)]
    pub fn into_name_and_hints(
        self,
    ) -> (
        Cow<'a, str>,
        Cow<'a, BTreeMap<RawAddress, ContextHint>>,
        Cow<'a, BTreeSet<RawAddress>>,
    ) {
        (self.name, self.mapping_hints, self.function_hints)
    }

    pub fn with_backing(mut self, backing: impl Into<Option<ImageBacking>>) -> Self {
        self.set_backing(backing);
        self
    }

    pub fn with_function_hints(
        mut self,
        function_hints: impl Into<Cow<'a, BTreeSet<RawAddress>>>,
    ) -> Self {
        self.set_function_hints(function_hints);
        self
    }

    pub fn with_mapping_hints(
        mut self,
        mapping_hints: impl Into<Cow<'a, BTreeMap<RawAddress, ContextHint>>>,
    ) -> Self {
        self.set_mapping_hints(mapping_hints);
        self
    }

    pub fn with_provenance(mut self, provenance: impl Into<SegmentMappingProvenance>) -> Self {
        self.set_provenance(provenance);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSegmentBytes<'a> {
    address: Address,
    bytes: Cow<'a, [u8]>,
    function_hints: BTreeSet<Address>,
    properties: SegmentProperties,
}

impl<'a> ImageSegmentBytes<'a> {
    pub fn new(
        address: Address,
        properties: SegmentProperties,
        bytes: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        Self {
            address,
            bytes: bytes.into(),
            function_hints: BTreeSet::new(),
            properties,
        }
    }

    pub fn add_function_hint(&mut self, address: impl Into<Address>) {
        self.function_hints.insert(address.into());
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Cow<'a, [u8]> {
        self.bytes
    }

    pub fn into_owned(self) -> ImageSegmentBytes<'static> {
        ImageSegmentBytes {
            address: self.address,
            bytes: Cow::Owned(self.bytes.into_owned()),
            function_hints: self.function_hints,
            properties: self.properties,
        }
    }

    pub fn into_write_at(
        self,
        bank: ImageBankHandle,
        offset: impl Into<RawAddress>,
    ) -> ImageWrite<'a> {
        ImageWrite::new(bank, offset, self.bytes)
    }

    pub fn function_hints(&self) -> &BTreeSet<Address> {
        &self.function_hints
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn contains_address(&self, address: Address) -> bool {
        self.offset_of(address).is_some()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    pub fn offset_of(&self, address: Address) -> Option<usize> {
        let delta = address.checked_offset_from(self.address)?;
        (delta < self.bytes.len() as u64).then_some(delta as usize)
    }

    pub fn read_value<T: ByteCast>(&self, offset: usize) -> Option<T> {
        let range = self.view_bytes_at(offset, T::SIZEOF)?;
        Some(if self.properties.is_big_endian() {
            T::from_bytes::<BE>(range)
        } else {
            T::from_bytes::<LE>(range)
        })
    }

    pub fn update_value<T: ByteCast>(
        &mut self,
        offset: usize,
        f: impl FnOnce(T) -> T,
    ) -> Option<()> {
        let is_be = self.properties.is_big_endian();
        let range = self.view_bytes_at_mut(offset, T::SIZEOF)?;

        if is_be {
            f(T::from_bytes::<BE>(range)).into_bytes::<BE>(range);
        } else {
            f(T::from_bytes::<LE>(range)).into_bytes::<LE>(range);
        }

        Some(())
    }

    pub fn write_value<T: ByteCast>(&mut self, offset: usize, value: T) -> Option<()> {
        let is_be = self.properties.is_big_endian();
        let range = self.view_bytes_at_mut(offset, T::SIZEOF)?;

        if is_be {
            value.into_bytes::<BE>(range);
        } else {
            value.into_bytes::<LE>(range);
        }

        Some(())
    }

    pub fn view_bytes_at(&self, offset: usize, count: usize) -> Option<&[u8]> {
        let end = offset.checked_add(count)?;
        (end <= self.bytes.len()).then_some(&self.bytes[offset..end])
    }

    pub fn view_bytes_at_mut(&mut self, offset: usize, count: usize) -> Option<&mut [u8]> {
        let end = offset.checked_add(count)?;
        (end <= self.bytes.len()).then_some(&mut self.bytes.to_mut()[offset..end])
    }
}

pub type ImageSegmentIterator<'a> =
    Box<dyn FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a>;
pub type ImageWriteIterator<'a> =
    Box<dyn FallibleIterator<Item = ImageWrite<'a>, Error = LoaderError> + 'a>;

pub struct DefaultBankWrites<I> {
    inner: I,
    bank_base: RawAddress,
}

impl<I> DefaultBankWrites<I> {
    pub fn new(inner: I, bank_base: impl Into<RawAddress>) -> Self {
        Self {
            inner,
            bank_base: bank_base.into(),
        }
    }
}

impl<'a, I> FallibleIterator for DefaultBankWrites<I>
where
    I: FallibleIterator<Item = ImageSegmentBytes<'a>, Error = LoaderError>,
{
    type Item = ImageWrite<'a>;
    type Error = LoaderError;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        let Some(bytes) = self.inner.next()? else {
            return Ok(None);
        };

        let offset = bytes
            .address()
            .offset()
            .checked_sub(self.bank_base.offset())
            .ok_or_else(|| LoaderError::address_overflow(bytes.address()))?;

        Ok(Some(
            bytes.into_write_at(ImageBankHandle::default(), offset),
        ))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageResolution {
    banks: BTreeMap<ImageBankHandle, SegmentStorageProviderId>,
    spaces: BTreeMap<ImageSpaceHandle, AddressSpaceId>,
}

impl ImageResolution {
    pub fn insert_bank(&mut self, bank: ImageBankHandle, provider: SegmentStorageProviderId) {
        self.banks.insert(bank, provider);
    }

    pub fn insert_space(&mut self, space: ImageSpaceHandle, target: AddressSpaceId) {
        self.spaces.insert(space, target);
    }

    pub fn banks(&self) -> &BTreeMap<ImageBankHandle, SegmentStorageProviderId> {
        &self.banks
    }

    pub fn resolve_address(&self, address: ImageAddress) -> Option<Address> {
        let space = self.spaces.get(&address.space()).copied()?;
        Some(Address::new(space, address.offset()))
    }

    pub fn resolve_bank(&self, bank: ImageBankHandle) -> Option<SegmentStorageProviderId> {
        self.banks.get(&bank).copied()
    }

    pub fn resolve_space(&self, space: ImageSpaceHandle) -> Option<AddressSpaceId> {
        self.spaces.get(&space).copied()
    }

    pub fn spaces(&self) -> &BTreeMap<ImageSpaceHandle, AddressSpaceId> {
        &self.spaces
    }
}
