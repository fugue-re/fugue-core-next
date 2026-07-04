use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::fmt;
use std::ops::{Add, Range};

use arrayvec::ArrayVec;
use fallible_iterator::FallibleIterator;
use fugue_bytes::{BE, ByteCast, LE};
use smallvec::{SmallVec, smallvec};

use crate::ir::{Address, Endian, RawAddress, SegmentProperties};
use crate::lifter::ContextHint;
use crate::loader::LoaderError;
use crate::storage::segments::SegmentStorageProviderId;
use crate::storage::segments::mapping::SegmentMappingProvenance;
use crate::storage::segments::space::AddressSpaceId;

const MAX_PATCH_SIZE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ImageSegmentChunk<'a> {
    Data(Cow<'a, [u8]>),
    Patch(ArrayVec<u8, MAX_PATCH_SIZE>),
}

impl<'a> ImageSegmentChunk<'a> {
    fn new(bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        ImageSegmentChunk::Data(bytes.into())
    }

    fn patch(bytes: &[u8]) -> Self {
        let mut patch = ArrayVec::new();
        patch
            .try_extend_from_slice(bytes)
            .expect("patch exceeds MAX_PATCH_SIZE bytes");
        ImageSegmentChunk::Patch(patch)
    }

    fn len(&self) -> usize {
        match self {
            ImageSegmentChunk::Data(data) => data.len(),
            ImageSegmentChunk::Patch(patch) => patch.len(),
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            ImageSegmentChunk::Data(data) => data,
            ImageSegmentChunk::Patch(patch) => patch,
        }
    }

    fn slice(self, from: usize, to: usize) -> ImageSegmentChunk<'a> {
        match self {
            ImageSegmentChunk::Data(Cow::Borrowed(slice)) => {
                ImageSegmentChunk::new(&slice[from..to])
            }
            ImageSegmentChunk::Data(Cow::Owned(mut owned)) => {
                owned.truncate(to);
                owned.drain(..from);
                ImageSegmentChunk::Data(Cow::Owned(owned))
            }
            ImageSegmentChunk::Patch(patch) => ImageSegmentChunk::patch(&patch[from..to]),
        }
    }

    fn split(
        self,
        head_to: usize,
        tail_from: usize,
    ) -> (ImageSegmentChunk<'a>, ImageSegmentChunk<'a>) {
        match self {
            ImageSegmentChunk::Data(Cow::Borrowed(slice)) => (
                ImageSegmentChunk::new(&slice[..head_to]),
                ImageSegmentChunk::new(&slice[tail_from..]),
            ),
            ImageSegmentChunk::Data(Cow::Owned(mut owned)) => {
                let tail = owned.split_off(tail_from);
                owned.truncate(head_to);
                (
                    ImageSegmentChunk::Data(Cow::Owned(owned)),
                    ImageSegmentChunk::new(tail),
                )
            }
            ImageSegmentChunk::Patch(patch) => (
                ImageSegmentChunk::patch(&patch[..head_to]),
                ImageSegmentChunk::patch(&patch[tail_from..]),
            ),
        }
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
pub struct ImageBankHandle(u16);

impl ImageBankHandle {
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(&self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for ImageBankHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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

impl fmt::Display for ImageSpaceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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

    pub fn raw_offset(&self) -> u64 {
        self.offset.offset()
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
    Base { bank: Option<ImageBankHandle> },
    Overlay { base: ImageSpaceHandle },
}

impl ImageSpaceKind {
    pub fn base() -> Self {
        Self::Base { bank: None }
    }

    pub fn base_with(bank: ImageBankHandle) -> Self {
        Self::Base { bank: Some(bank) }
    }

    pub fn overlay(base: ImageSpaceHandle) -> Self {
        Self::Overlay { base }
    }
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

    pub fn base(handle: ImageSpaceHandle) -> Self {
        Self::new(handle, ImageSpaceKind::base())
    }

    pub fn base_with(handle: ImageSpaceHandle, bank: ImageBankHandle) -> Self {
        Self::new(handle, ImageSpaceKind::base_with(bank))
    }

    pub fn overlay(handle: ImageSpaceHandle, base: ImageSpaceHandle) -> Self {
        Self::new(handle, ImageSpaceKind::overlay(base))
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
            smallvec![ImageSpace::base(space)],
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
    bytes: ImageSegmentChunk<'a>,
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
            bytes: ImageSegmentChunk::new(bytes),
            offset: offset.into(),
        }
    }

    fn patch(
        bank: ImageBankHandle,
        offset: impl Into<RawAddress>,
        patch: ArrayVec<u8, MAX_PATCH_SIZE>,
    ) -> Self {
        Self {
            bank,
            bytes: ImageSegmentChunk::Patch(patch),
            offset: offset.into(),
        }
    }

    pub fn bank(&self) -> ImageBankHandle {
        self.bank
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.bytes()
    }

    pub fn offset(&self) -> RawAddress {
        self.offset
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
        let bank_offset = address
            .offset()
            .checked_sub(bank_base)
            .expect("segment address is below its bank base");
        Self::new(name, address, size, properties)
            .with_backing(ImageBacking::in_default_bank(bank_offset))
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

    pub fn set_function_hints(&mut self, function_hints: impl Into<BTreeSet<RawAddress>>) {
        self.function_hints = Cow::Owned(function_hints.into());
    }

    pub fn set_mapping_hints(
        &mut self,
        mapping_hints: impl Into<BTreeMap<RawAddress, ContextHint>>,
    ) {
        self.mapping_hints = Cow::Owned(mapping_hints.into());
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

    pub fn with_function_hints(mut self, function_hints: impl Into<BTreeSet<RawAddress>>) -> Self {
        self.set_function_hints(function_hints);
        self
    }

    pub fn with_mapping_hints(
        mut self,
        mapping_hints: impl Into<BTreeMap<RawAddress, ContextHint>>,
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
pub struct ImageSegmentContents<'a> {
    address: RawAddress,
    len: u64,
    chunks: BTreeMap<usize, ImageSegmentChunk<'a>>,
    function_hints: BTreeSet<RawAddress>,
    mapping_hints: BTreeMap<RawAddress, ContextHint>,
    endian: Endian,
    bank: ImageBankHandle,
}

impl<'a> ImageSegmentContents<'a> {
    pub fn new(
        address: impl Into<RawAddress>,
        endian: Endian,
        bytes: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        let data = bytes.into();
        let len = data.len() as u64;
        Self::from_data(address.into(), endian, data, len)
    }

    pub fn new_sparse(
        address: impl Into<RawAddress>,
        endian: Endian,
        bytes: impl Into<Cow<'a, [u8]>>,
        len: u64,
    ) -> Self {
        Self::from_data(address.into(), endian, bytes.into(), len)
    }

    fn from_data(address: RawAddress, endian: Endian, data: Cow<'a, [u8]>, len: u64) -> Self {
        let mut chunks = BTreeMap::new();
        if !data.is_empty() {
            chunks.insert(0, ImageSegmentChunk::new(data));
        }
        Self {
            address,
            len,
            chunks,
            function_hints: BTreeSet::new(),
            mapping_hints: BTreeMap::new(),
            endian,
            bank: ImageBankHandle::default(),
        }
    }

    pub fn with_bank(mut self, bank: ImageBankHandle) -> Self {
        self.bank = bank;
        self
    }

    pub fn bank(&self) -> ImageBankHandle {
        self.bank
    }

    pub fn add_function_hint(&mut self, offset: impl Into<RawAddress>) {
        self.function_hints.insert(offset.into());
    }

    pub fn add_mapping_hint(&mut self, offset: impl Into<RawAddress>, hint: ContextHint) {
        self.mapping_hints.insert(offset.into(), hint);
    }

    pub fn address(&self) -> RawAddress {
        self.address
    }

    pub fn into_writes(
        self,
        bank_base: RawAddress,
    ) -> Result<ImageSegmentChunkWrites<'a>, LoaderError> {
        let segment_offset = self
            .address
            .checked_sub(bank_base)
            .ok_or_else(|| LoaderError::address_overflow(self.address))?;

        Ok(ImageSegmentChunkWrites {
            bank: self.bank,
            segment_offset,
            chunks: self.chunks.into_iter(),
        })
    }

    pub fn function_hints(&self) -> &BTreeSet<RawAddress> {
        &self.function_hints
    }

    pub fn mapping_hints(&self) -> &BTreeMap<RawAddress, ContextHint> {
        &self.mapping_hints
    }

    pub fn take_function_hints(&mut self) -> BTreeSet<RawAddress> {
        std::mem::take(&mut self.function_hints)
    }

    pub fn take_mapping_hints(&mut self) -> BTreeMap<RawAddress, ContextHint> {
        std::mem::take(&mut self.mapping_hints)
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn contains_address(&self, address: impl Into<RawAddress>) -> bool {
        self.offset_of(address).is_some()
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn offset_of(&self, address: impl Into<RawAddress>) -> Option<u64> {
        let delta = address.into().checked_offset_from(self.address)?;
        (delta < self.len).then_some(delta)
    }

    pub fn read_value<T: ByteCast>(&self, offset: u64) -> Option<T> {
        if offset.checked_add(T::SIZEOF as u64)? > self.len {
            return None;
        }
        let offset = usize::try_from(offset).ok()?;

        let mut buf = SmallVec::<[u8; MAX_PATCH_SIZE]>::from_elem(0, T::SIZEOF);
        self.read_into(offset, &mut buf);

        Some(if self.endian.is_big() {
            T::from_bytes::<BE>(&buf)
        } else {
            T::from_bytes::<LE>(&buf)
        })
    }

    pub fn update_value<T: ByteCast>(&mut self, offset: u64, f: impl FnOnce(T) -> T) -> Option<()> {
        let value = self.read_value::<T>(offset)?;
        self.write_value(offset, f(value))
    }

    pub fn write_value<T: ByteCast>(&mut self, offset: u64, value: T) -> Option<()> {
        if offset.checked_add(T::SIZEOF as u64)? > self.len {
            return None;
        }
        let offset = usize::try_from(offset).ok()?;

        let mut buf = SmallVec::<[u8; MAX_PATCH_SIZE]>::from_elem(0, T::SIZEOF);
        if self.endian.is_big() {
            value.into_bytes::<BE>(&mut buf);
        } else {
            value.into_bytes::<LE>(&mut buf);
        }

        for (i, chunk) in buf.chunks(MAX_PATCH_SIZE).enumerate() {
            self.write_at(offset + i * MAX_PATCH_SIZE, chunk);
        }
        Some(())
    }

    fn read_into(&self, offset: usize, out: &mut [u8]) {
        out.fill(0);
        let end = offset + out.len();
        let lower = self
            .chunks
            .range(..=offset)
            .next_back()
            .map(|(&start, _)| start)
            .unwrap_or(offset);

        for (&start, chunk) in self.chunks.range(lower..end) {
            let chunk_end = start + chunk.len();
            if chunk_end <= offset {
                continue;
            }
            let overlap_start = offset.max(start);
            let overlap_end = end.min(chunk_end);
            if overlap_start >= overlap_end {
                continue;
            }
            let src = &chunk.bytes()[overlap_start - start..overlap_end - start];
            out[overlap_start - offset..overlap_end - offset].copy_from_slice(src);
        }
    }

    fn write_at(&mut self, offset: usize, data: &[u8]) {
        let end = offset + data.len();
        let lower = self
            .chunks
            .range(..=offset)
            .next_back()
            .map(|(&start, _)| start)
            .unwrap_or(offset);

        let overlapping = self
            .chunks
            .range(lower..end)
            .filter(|(start, chunk)| **start + chunk.len() > offset)
            .map(|(&start, _)| start)
            .collect::<SmallVec<[usize; 4]>>();

        let mut remainders = SmallVec::<[(usize, ImageSegmentChunk<'a>); 2]>::new();
        for start in overlapping {
            let chunk = self.chunks.remove(&start).unwrap();
            let chunk_end = start + chunk.len();
            match (start < offset, chunk_end > end) {
                (true, true) => {
                    let (head, tail) = chunk.split(offset - start, end - start);
                    remainders.push((start, head));
                    remainders.push((end, tail));
                }
                (true, false) => remainders.push((start, chunk.slice(0, offset - start))),
                (false, true) => {
                    remainders.push((end, chunk.slice(end - start, chunk_end - start)))
                }
                (false, false) => {}
            }
        }

        self.chunks.insert(offset, ImageSegmentChunk::patch(data));
        for (start, chunk) in remainders {
            self.chunks.insert(start, chunk);
        }
    }
}

pub type ImageSegmentIterator<'a> =
    Box<dyn FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a>;
pub type ImageSegmentContentsIterator<'a> =
    Box<dyn FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a>;

pub struct ImageSegmentChunkWrites<'a> {
    bank: ImageBankHandle,
    segment_offset: RawAddress,
    chunks: btree_map::IntoIter<usize, ImageSegmentChunk<'a>>,
}

impl<'a> Iterator for ImageSegmentChunkWrites<'a> {
    type Item = ImageWrite<'a>;

    fn next(&mut self) -> Option<ImageWrite<'a>> {
        let (offset, chunk) = self.chunks.next()?;
        let offset = self.segment_offset + offset;
        Some(match chunk {
            ImageSegmentChunk::Data(data) => ImageWrite::new(self.bank, offset, data),
            ImageSegmentChunk::Patch(patch) => ImageWrite::patch(self.bank, offset, patch),
        })
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
