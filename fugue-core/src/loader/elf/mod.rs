use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;
use std::path::Path;
use std::slice;
use std::sync::OnceLock;

use bitflags::bitflags;
use fallible_iterator::FallibleIterator;
use object::elf::{
    ELFOSABI_FREEBSD, FileHeader32, FileHeader64, PF_R, PF_W, PF_X, SHF_ALLOC, SHF_EXECINSTR,
    SHF_TLS, SHF_WRITE, STB_GLOBAL, STB_WEAK, STT_COMMON, STT_FUNC, STT_GNU_IFUNC, STT_LOOS,
    STT_NOTYPE, STT_OBJECT, STT_TLS,
};
use object::read::elf::{
    self, ElfFile, ElfSection, ElfSectionIterator, ElfSegmentIterator, FileHeader,
};
use object::{
    Endianness, FileKind, Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, ReadRef,
    SectionFlags, SectionIndex, SectionKind, SegmentFlags, SymbolFlags,
};
use smallvec::{SmallVec, smallvec};

use crate::AnalysisData;
use crate::arch::Arch;
use crate::ir::{
    RawAddress, RawAddressRangeSet, Symbol, SymbolIndex, SymbolProperties, SymbolTableSelector,
    TransientSymbolTable,
};
use crate::lifter::ContextHint;
use crate::loader::elf::extensions::ImageContext;
use crate::loader::{
    ExternalThunkLayout, ImageAddress, ImageBacking, ImageBank, ImageBankHandle, ImageBankLayout,
    ImageCoveredRegions, ImageLayout, ImageRegionBankMap, ImageSegment, ImageSegmentContents,
    ImageSegmentContentsIterator, ImageSegmentIterator, ImageSpace, ImageSpaceHandle, ImageSpaces,
    Loadable, LoadableFromBytes, LoadableFromFile, LoadableMetadata, LoaderError,
};
use crate::platform::{Format, OperatingSystem, Platform};
use crate::storage::segments::SegmentProperties;
use crate::storage::segments::mapping::SegmentMappingProvenance;
use crate::types::attributes::{ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_IMAGE_BASE};
use crate::types::{AttributeMap, BytesOrMapping};

mod function_recovery;

pub mod extensions;

mod relocations;
pub use relocations::ElfSegmentRelocator;

const STT_GNU_UNIQUE: u8 = STT_LOOS;

pub const ELF_SYMTAB_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(0);
pub const ELF_DYNSYM_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(1);

pub const ATTRIBUTE_OVERRIDE_SEGMENT_PERMISSIONS: &str = "loader.elf.override_segment_permissions";
pub const ATTRIBUTE_SKIP_NOTE_SECTIONS: &str = "loader.elf.skip_note_sections";
pub const ATTRIBUTE_PRESERVE_RELOCATABLE_SECTION_ADDRESSES: &str =
    "loader.elf.preserve_relocatable_section_addresses";
pub const ATTRIBUTE_LOAD_HEADERS: &str = "loader.elf.load_headers";

#[ouroboros::self_referencing]
struct ElfInner<'a> {
    data: BytesOrMapping<'a>,
    #[borrows(data)]
    #[covariant]
    view: ElfFileRepr<'this, 'a>,
}

pub enum ElfFileRepr<'this, 'data> {
    Elf32(ElfFile<'this, FileHeader32<Endianness>, &'this BytesOrMapping<'data>>),
    Elf64(ElfFile<'this, FileHeader64<Endianness>, &'this BytesOrMapping<'data>>),
}

macro_rules! with_elf {
    ($inner:expr, $var:ident | $body:expr) => {
        match $inner {
            ElfFileRepr::Elf32($var) => $body,
            ElfFileRepr::Elf64($var) => $body,
        }
    };
}

impl<'this, 'data> ElfFileRepr<'this, 'data> {
    fn parse(data: &'this BytesOrMapping<'data>) -> Result<Self, LoaderError> {
        let elf = match FileKind::parse(data).map_err(LoaderError::format)? {
            FileKind::Elf32 => {
                Self::Elf32(elf::ElfFile32::parse(data).map_err(LoaderError::format)?)
            }
            FileKind::Elf64 => {
                Self::Elf64(elf::ElfFile64::parse(data).map_err(LoaderError::format)?)
            }
            _ => {
                return Err(LoaderError::format_with("input is not an ELF"));
            }
        };
        Ok(elf)
    }

    pub(crate) fn is_64(&self) -> bool {
        with_elf!(self, elf | elf.is_64())
    }

    pub(crate) fn is_big_endian(&self) -> bool {
        with_elf!(self, elf | !elf.is_little_endian())
    }

    pub(crate) fn machine(&self) -> u16 {
        with_elf!(self, elf | elf.elf_header().e_machine(elf.endian()))
    }

    pub(crate) fn flags(&self) -> u32 {
        with_elf!(self, elf | elf.elf_header().e_flags(elf.endian()))
    }
}

#[derive(AnalysisData)]
pub struct Elf<'a> {
    object: ElfInner<'a>,
    architecture: Arch,
    metadata: OnceLock<LoadableMetadata>,
    path: Option<String>,
    base: RawAddress,
    preferred_base: RawAddress,
    entry: Option<ImageAddress>,
    layout: ImageLayout,
    image_symbols: TransientSymbolTable<ImageAddress>,
    mapping_hints: BTreeMap<RawAddress, ContextHint>,
    segments: Vec<ElfImageSegment>,
    region_bank: ElfRegionBankMap,
    sections: ElfSectionMap,
    external_thunks: ExternalThunkLayout,
    attributes: AttributeMap,
}

impl<'a> Elf<'a> {
    pub fn new(data: impl Into<BytesOrMapping<'a>>) -> Result<Self, LoaderError> {
        Self::new_with(data, AttributeMap::new())
    }

    pub fn new_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        let object = ElfInner::try_new(data.into(), |data| ElfFileRepr::parse(data))?;

        let attributes = attributes.into();
        let view = object.borrow_view();

        let preferred_base = with_elf!(
            view,
            elf | elf
                .segments()
                .filter(|segm| segm.size() != 0)
                .map(|segm| segm.address())
                .min()
                .unwrap_or_default()
        )
        .into();

        let base = attributes
            .get_attr::<RawAddress>(ATTRIBUTE_IMAGE_BASE)
            .unwrap_or(preferred_base);

        if base != preferred_base && with_elf!(view, elf | elf.kind()) == ObjectKind::Executable {
            return Err(LoaderError::format_with(
                "cannot rebase a non-relocatable ELF executable",
            ));
        }

        let entry = with_elf!(view, elf | elf.entry());
        let entry = (entry != 0).then(|| (base - preferred_base) + entry);
        let context = ImageContext::new(view, base, preferred_base, entry, &attributes);
        let architecture = context.resolve_architecture()?;

        let config = ElfLoaderProperties::new(&attributes);

        let ElfSymbolLayout {
            bounds,
            symbols,
            sections,
            mapping_hints,
            external_thunks,
        } = with_elf!(
            view,
            elf | ElfSymbolLayout::from_elf(elf, &architecture, base, preferred_base, config)?
        );

        let header_last = config
            .load_headers()
            .then(|| {
                with_elf!(
                    view,
                    elf | elf
                        .data()
                        .len()
                        .ok()
                        .and_then(|len| base.checked_add(len.checked_sub(1)?))
                )
            })
            .flatten();
        let bank_base = if config.load_headers() {
            base.min(*bounds.start())
        } else {
            *bounds.start()
        };
        let bank_last = header_last
            .map_or(*bounds.end(), |last| last.max(*bounds.end()))
            .checked_offset_from(bank_base)
            .and_then(|size| bank_base.checked_add(size))
            .ok_or_else(|| LoaderError::address_overflow(base))?;

        let default_bank = ImageBank::new_in_default(bank_base..=bank_last);
        let (placements, spaces, bank_layout) = with_elf!(
            view,
            elf | {
                let mut walk = ElfSegmentWalk::new(
                    elf,
                    base,
                    preferred_base,
                    default_bank,
                    &sections,
                    &external_thunks,
                    config,
                )?;
                while let Some(region) = walk.next_region() {
                    walk.place_region(region)?;
                }
                walk.into_parts()
            }
        );
        let (banks, region_bank) = bank_layout.into_parts();

        let mut symbol_indices_by_offset =
            BTreeMap::<RawAddress, SmallVec<[SymbolIndex; 1]>>::new();
        for (index, symbol) in &symbols {
            symbol_indices_by_offset
                .entry(symbol.address)
                .or_default()
                .push(*index);
        }

        let mut space_by_index = BTreeMap::<SymbolIndex, ImageSpaceHandle>::new();
        for placement in &placements {
            let start = placement.address.offset();
            let Some(last) = start.checked_add(placement.size.saturating_sub(1)) else {
                continue;
            };
            let covered = symbol_indices_by_offset
                .range(start..=last)
                .map(|(offset, _)| *offset)
                .collect::<SmallVec<[RawAddress; 8]>>();
            for offset in covered {
                let Some(indices) = symbol_indices_by_offset.remove(&offset) else {
                    continue;
                };
                for index in indices {
                    space_by_index.insert(index, placement.space());
                }
            }
        }

        let mut image_symbols = TransientSymbolTable::<ImageAddress>::new();
        for (index, symbol) in symbols {
            let space = space_by_index.get(&index).copied().unwrap_or_default();
            image_symbols.insert(
                index,
                ImageAddress::new(space, symbol.address),
                symbol.symbol,
                symbol.properties,
            );
        }

        let layout = ImageLayout::new(banks, spaces);

        let entry = entry.map(ImageAddress::in_default_space);

        let mut slf = Self {
            object,
            architecture,
            metadata: OnceLock::new(),
            path: None,
            base,
            preferred_base,
            entry,
            image_symbols,
            layout,
            mapping_hints,
            segments: placements,
            region_bank,
            sections,
            external_thunks,
            attributes,
        };

        if let Some(entry) = slf.entry() {
            slf.attributes.set_attr(ATTRIBUTE_ENTRY_POINT, entry);
        }

        Ok(slf)
    }

    pub fn loaded_view(&self) -> &ElfFileRepr<'_, 'a> {
        self.object.borrow_view()
    }

    pub fn mapping_hints(&self) -> &BTreeMap<RawAddress, ContextHint> {
        &self.mapping_hints
    }

    pub fn image_symbols(&self) -> &TransientSymbolTable<ImageAddress> {
        &self.image_symbols
    }

    pub fn external_thunks(&self) -> &ExternalThunkLayout {
        &self.external_thunks
    }

    pub fn base_address(&self) -> RawAddress {
        self.base
    }

    pub fn is_object(&self) -> bool {
        with_elf!(
            self.object.borrow_view(),
            elf | elf.kind() == ObjectKind::Relocatable
        )
    }

    pub fn entry(&self) -> Option<RawAddress> {
        let addr = with_elf!(self.object.borrow_view(), elf | elf.entry());
        (addr != 0).then(|| (self.base - self.preferred_base) + addr)
    }

    pub fn operating_system(&self) -> OperatingSystem {
        let os_abi = with_elf!(
            self.object.borrow_view(),
            elf | elf.elf_header().e_ident().os_abi
        );

        match os_abi {
            ELFOSABI_FREEBSD => OperatingSystem::FreeBsd,
            _ => OperatingSystem::Linux,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ElfSectionMap(Vec<Option<RawAddress>>);

impl ElfSectionMap {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self, index: usize) -> Option<RawAddress> {
        self.0.get(index).copied().flatten()
    }

    fn insert(&mut self, index: usize, address: RawAddress) {
        if index >= self.0.len() {
            self.0.resize(index + 1, None);
        }
        self.0[index] = Some(address);
    }
}

struct ElfRegion<'data> {
    name: Cow<'data, str>,
    address: RawAddress,
    size: u64,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
    file_offset: Option<u64>,
    source: Option<ElfRegionSource>,
}

impl ElfRegion<'_> {
    fn source(&self) -> Option<ElfRegionSource> {
        self.source
    }

    fn section_source(&self) -> Option<ElfRegionSource> {
        self.source.filter(|source| source.is_section())
    }
}

struct ElfImageSegment {
    name: String,
    address: ImageAddress,
    backing_offset: RawAddress,
    size: u64,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
    bank: ImageBankHandle,
}

impl ElfImageSegment {
    fn new(region: &ElfRegion, space: ImageSpaceHandle, backing_offset: RawAddress) -> Self {
        Self {
            name: region.name.as_ref().to_owned(),
            address: ImageAddress::new(space, region.address),
            backing_offset,
            size: region.size,
            properties: region.properties,
            provenance: region.provenance,
            bank: ImageBankHandle::default(),
        }
    }

    fn space(&self) -> ImageSpaceHandle {
        self.address.space()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ElfRegionSourceKind {
    Header,
    Section,
    Segment,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ElfRegionSource {
    kind: ElfRegionSourceKind,
    index: usize,
}

impl ElfRegionSource {
    fn new(kind: ElfRegionSourceKind, index: usize) -> Self {
        Self { kind, index }
    }

    fn section(index: usize) -> Self {
        Self::new(ElfRegionSourceKind::Section, index)
    }

    fn segment(index: usize) -> Self {
        Self::new(ElfRegionSourceKind::Segment, index)
    }

    fn header(index: usize) -> Self {
        Self::new(ElfRegionSourceKind::Header, index)
    }

    fn kind(self) -> ElfRegionSourceKind {
        self.kind
    }

    fn is_kind(self, kind: ElfRegionSourceKind) -> bool {
        self.kind() == kind
    }

    fn is_section(self) -> bool {
        self.is_kind(ElfRegionSourceKind::Section)
    }

    fn is_segment(self) -> bool {
        self.is_kind(ElfRegionSourceKind::Segment)
    }

    fn is_header(self) -> bool {
        self.is_kind(ElfRegionSourceKind::Header)
    }
}

type ElfCoveredRegions = ImageCoveredRegions;
type ElfRegionBankMap = ImageRegionBankMap<ElfRegionSource>;
type ElfBankLayout = ImageBankLayout<ElfRegionSource>;

struct ElfSectionRevIterator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    elf: &'file ElfFile<'data, Elf, R>,
    cursor: usize,
}

struct ElfHeaderRegion<'data> {
    name: &'static str,
    address: RawAddress,
    file_offset: u64,
    data: &'data [u8],
    source: ElfRegionSource,
}

impl<'data> ElfHeaderRegion<'data> {
    fn new(
        name: &'static str,
        address: RawAddress,
        file_offset: u64,
        data: &'data [u8],
        source: ElfRegionSource,
    ) -> Self {
        Self {
            name,
            address,
            file_offset,
            data,
            source,
        }
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn data(&self) -> &'data [u8] {
        self.data
    }
}

struct ElfHeaderRegions<'data> {
    regions: SmallVec<[ElfHeaderRegion<'data>; 3]>,
}

impl<'data> ElfHeaderRegions<'data> {
    fn new<Elf, R>(
        elf: &ElfFile<'data, Elf, R>,
        base: RawAddress,
        preferred_base: RawAddress,
    ) -> Result<Self, LoaderError>
    where
        Elf: FileHeader,
        R: ReadRef<'data>,
    {
        let endian = elf.endian();
        let header = elf.elf_header();

        let ph_size = u64::from(header.e_phentsize(endian)) * u64::from(header.e_phnum(endian));
        let sh_size = u64::from(header.e_shentsize(endian)) * u64::from(header.e_shnum(endian));

        let ranges = [
            ("_elfHeader", 0u64, u64::from(header.e_ehsize(endian))),
            ("_elfProgramHeaders", header.e_phoff(endian).into(), ph_size),
            ("_elfSectionHeaders", header.e_shoff(endian).into(), sh_size),
        ];

        let mut regions = SmallVec::<[ElfHeaderRegion<'data>; 3]>::new();
        for (index, (name, file_offset, size)) in ranges.into_iter().enumerate() {
            if let Some(region) =
                Self::file_range(elf, base, preferred_base, name, file_offset, size, index)?
            {
                regions.push(region);
            }
        }
        regions.reverse();

        Ok(Self { regions })
    }

    fn file_range<Elf, R>(
        elf: &ElfFile<'data, Elf, R>,
        base: RawAddress,
        preferred_base: RawAddress,
        name: &'static str,
        file_offset: u64,
        size: u64,
        index: usize,
    ) -> Result<Option<ElfHeaderRegion<'data>>, LoaderError>
    where
        Elf: FileHeader,
        R: ReadRef<'data>,
    {
        if size == 0 {
            return Ok(None);
        }
        let Ok(file_len) = elf.data().len() else {
            tracing::warn!("cannot determine file length for header `{name}`; skipping");
            return Ok(None);
        };
        if file_offset >= file_len {
            tracing::warn!(
                "header `{name}` file offset {file_offset:#x} exceeds file length {file_len:#x}; skipping"
            );
            return Ok(None);
        }
        let size = size.min(file_len - file_offset);
        let Ok(data) = elf.data().read_bytes_at(file_offset, size) else {
            tracing::warn!("cannot read header `{name}` at offset {file_offset:#x}; skipping");
            return Ok(None);
        };
        let address =
            match Self::load_address_for_file_range(elf, base, preferred_base, file_offset, size) {
                Some(address) => address,
                None => base
                    .checked_add(file_offset)
                    .ok_or_else(|| LoaderError::address_overflow(base))?,
            };
        Ok(Some(ElfHeaderRegion::new(
            name,
            address,
            file_offset,
            data,
            ElfRegionSource::header(index),
        )))
    }

    fn load_address_for_file_range<Elf, R>(
        elf: &ElfFile<'data, Elf, R>,
        base: RawAddress,
        preferred_base: RawAddress,
        file_offset: u64,
        size: u64,
    ) -> Option<RawAddress>
    where
        Elf: FileHeader,
        R: ReadRef<'data>,
    {
        let last_offset = file_offset.checked_add(size.checked_sub(1)?)?;
        elf.segments().find_map(|segment| {
            let (segment_offset, segment_size) = segment.file_range();
            if segment_size == 0 {
                return None;
            }
            let segment_last = segment_offset.checked_add(segment_size.checked_sub(1)?)?;
            if file_offset < segment_offset || last_offset > segment_last {
                return None;
            }
            let delta = file_offset.checked_sub(segment_offset)?;
            let address = base
                .checked_sub(preferred_base)?
                .checked_add(segment.address())?;
            address.checked_add(delta)
        })
    }
}

impl<'data> Iterator for ElfHeaderRegions<'data> {
    type Item = ElfHeaderRegion<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.regions.pop()
    }
}

impl<'data, 'file, Elf, R> ElfSectionRevIterator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    fn new(elf: &'file ElfFile<'data, Elf, R>) -> Self {
        Self {
            elf,
            cursor: elf.elf_section_table().len(),
        }
    }
}

impl<'data, 'file, Elf, R> Iterator for ElfSectionRevIterator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    type Item = ElfSection<'data, 'file, Elf, R>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.cursor > 0 {
            self.cursor -= 1;
            if let Ok(section) = self.elf.section_by_index(SectionIndex(self.cursor)) {
                return Some(section);
            }
        }
        None
    }
}

struct ElfSegmentWalk<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    base: RawAddress,
    preferred_base: RawAddress,
    bank_base: RawAddress,
    base_space: ImageSpaceHandle,
    sections: &'file ElfSectionMap,
    sects: ElfSectionRevIterator<'data, 'file, Elf, R>,
    segms: ElfSegmentIterator<'data, 'file, Elf, R>,
    headers: ElfHeaderRegions<'data>,
    external_thunks: Option<&'file ExternalThunkLayout>,
    covered: RawAddressRangeSet,
    spaces: ImageSpaces,
    bank_layout: ElfBankLayout,
    placements: Vec<ElfImageSegment>,
    placed_regions: Vec<ElfPlacedRegion>,
    segment_ordinal: usize,
    config: ElfLoaderProperties,
    is_object: bool,
}

struct ElfPlacedRegion {
    start: RawAddress,
    last: RawAddress,
    file_delta: u64,
    placement: usize,
    source: ElfRegionSource,
}

impl ElfPlacedRegion {
    fn new(
        start: RawAddress,
        last: RawAddress,
        file_delta: u64,
        placement: usize,
        source: ElfRegionSource,
    ) -> Self {
        Self {
            start,
            last,
            file_delta,
            placement,
            source,
        }
    }

    fn start(&self) -> RawAddress {
        self.start
    }

    fn last(&self) -> RawAddress {
        self.last
    }

    fn file_delta(&self) -> u64 {
        self.file_delta
    }

    fn placement(&self) -> usize {
        self.placement
    }

    fn source(&self) -> ElfRegionSource {
        self.source
    }
}

impl<'data, 'file, Elf, R> ElfSegmentWalk<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn new(
        elf: &'file ElfFile<'data, Elf, R>,
        base: RawAddress,
        preferred_base: RawAddress,
        default_bank: ImageBank,
        sections: &'file ElfSectionMap,
        external_thunks: &'file ExternalThunkLayout,
        mut config: ElfLoaderProperties,
    ) -> Result<Self, LoaderError> {
        let is_object = elf.kind() == ObjectKind::Relocatable;
        if is_object {
            config.insert(ElfLoaderProperties::IS_OBJECT);
        }
        let base_space = ImageSpaceHandle::default();
        let bank_base = *default_bank.range().start();
        Ok(Self {
            base,
            preferred_base,
            bank_base,
            base_space,
            sections,
            sects: ElfSectionRevIterator::new(elf),
            segms: elf.segments(),
            headers: ElfHeaderRegions::new(elf, base, preferred_base)?,
            external_thunks: Some(external_thunks),
            covered: RawAddressRangeSet::new(),
            spaces: smallvec![ImageSpace::base(base_space)],
            bank_layout: ElfBankLayout::new(default_bank),
            placements: Vec::new(),
            placed_regions: Vec::new(),
            segment_ordinal: 0,
            config,
            is_object,
        })
    }

    fn next_region(&mut self) -> Option<ElfRegion<'data>> {
        if self.config.load_headers()
            && let Some(header) = self.headers.next()
        {
            return Some(ElfRegion {
                name: Cow::Borrowed(header.name),
                address: header.address,
                size: header.size(),
                properties: SegmentProperties::PERM_READ,
                provenance: SegmentMappingProvenance::Section,
                file_offset: Some(header.file_offset),
                source: Some(header.source),
            });
        }

        if self.is_object {
            for sect in self.sects.by_ref() {
                let Some(address) = self.sections.get(sect.index().0) else {
                    continue;
                };
                return Some(ElfRegion {
                    name: Cow::Borrowed(sect.name().ok().unwrap_or("LOAD")),
                    address,
                    size: sect.size().max(1),
                    properties: elf_section_properties(&sect, &self.config),
                    provenance: SegmentMappingProvenance::Section,
                    file_offset: sect.file_range().map(|(off, _)| off),
                    source: Some(ElfRegionSource::section(sect.index().0)),
                });
            }
            return self.external_region();
        }

        for sect in self.sects.by_ref() {
            let SectionFlags::Elf { sh_flags } = sect.flags() else {
                continue;
            };
            let size = sect.size();
            if size == 0 || (sh_flags as u32 & SHF_ALLOC) != SHF_ALLOC {
                continue;
            }
            if (sh_flags as u32 & SHF_TLS) == SHF_TLS {
                tracing::debug!(
                    "skipping TLS section {}",
                    sect.name().unwrap_or("<unnamed>")
                );
                continue;
            }
            return Some(ElfRegion {
                name: Cow::Borrowed(sect.name().ok().unwrap_or("LOAD")),
                address: (self.base - self.preferred_base) + sect.address(),
                size,
                properties: elf_section_properties(&sect, &self.config),
                provenance: SegmentMappingProvenance::Section,
                file_offset: sect.file_range().map(|(off, _)| off),
                source: Some(ElfRegionSource::section(sect.index().0)),
            });
        }

        for segm in self.segms.by_ref() {
            let size = segm.size();
            if size == 0 {
                continue;
            }
            let name = segm
                .name()
                .ok()
                .flatten()
                .map(|name| Cow::Owned(name.to_owned()))
                .unwrap_or(Cow::Borrowed("LOAD"));
            let (file_off, file_size) = segm.file_range();
            return Some(ElfRegion {
                name,
                address: (self.base - self.preferred_base) + segm.address(),
                size,
                properties: elf_segment_properties(&segm, &self.config),
                provenance: SegmentMappingProvenance::Segment,
                file_offset: (file_size != 0).then_some(file_off),
                source: Some(ElfRegionSource::segment(self.next_segment_ordinal())),
            });
        }

        self.external_region()
    }

    fn external_region(&mut self) -> Option<ElfRegion<'data>> {
        let external_thunks = self
            .external_thunks
            .take()
            .filter(|layout| !layout.is_empty())?;
        Some(ElfRegion {
            name: Cow::Borrowed("EXTERNAL"),
            address: external_thunks.start(),
            size: external_thunks.size() as u64,
            properties: SegmentProperties::PERM_READ | SegmentProperties::PERM_EXECUTE,
            provenance: SegmentMappingProvenance::External,
            file_offset: None,
            source: None,
        })
    }

    fn next_segment_ordinal(&mut self) -> usize {
        let ordinal = self.segment_ordinal;
        self.segment_ordinal += 1;
        ordinal
    }

    fn next_overlay_space(&mut self) -> ImageSpaceHandle {
        let handle = ImageSpaceHandle::new(
            u16::try_from(self.spaces.len()).expect("space count must fit in u16"),
        );
        self.spaces
            .push(ImageSpace::overlay(handle, self.base_space));
        handle
    }

    fn push_placement(
        &mut self,
        region: &ElfRegion,
        space: ImageSpaceHandle,
        backing_offset: impl Into<RawAddress>,
    ) -> usize {
        let placement = self.placements.len();
        self.placements
            .push(ElfImageSegment::new(region, space, backing_offset.into()));
        placement
    }

    fn conflicting_base_regions(
        &self,
        kind: ElfRegionSourceKind,
        start: RawAddress,
        last: RawAddress,
        file_delta: u64,
    ) -> SmallVec<[usize; 2]> {
        self.placed_regions
            .iter()
            .enumerate()
            .filter(|(_, placed)| {
                placed.source().is_kind(kind)
                    && placed.file_delta() != file_delta
                    && start <= placed.last()
                    && placed.start() <= last
                    && self.placements[placed.placement()].space() == self.base_space
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn demote_section_if_conflicting(
        &mut self,
        source: ElfRegionSource,
        address: RawAddress,
        placement: usize,
        last: RawAddress,
        file_delta: u64,
    ) {
        let conflicts =
            self.conflicting_base_regions(ElfRegionSourceKind::Section, address, last, file_delta);
        if conflicts.is_empty() {
            return;
        }

        let bank = self.bank_layout.allocate_overlay(address..=last);
        let displaced = &mut self.placements[placement];
        displaced.bank = bank;
        displaced.backing_offset = RawAddress::from(0u64);
        self.bank_layout.route_region(source, bank);
    }

    fn place_overlapping_region(
        &mut self,
        region: &ElfRegion,
        backing_offset: RawAddress,
        last: RawAddress,
        file_delta: Option<u64>,
    ) -> Option<usize> {
        let base = region
            .source()
            .is_some_and(ElfRegionSource::is_segment)
            .then(|| self.push_placement(region, self.base_space, backing_offset));
        let overlay = self.next_overlay_space();
        let placement = self.push_placement(region, overlay, backing_offset);
        if let Some((source, delta)) = region.section_source().zip(file_delta) {
            self.demote_section_if_conflicting(source, region.address, placement, last, delta);
        }
        base
    }

    fn place_region(&mut self, region: ElfRegion) -> Result<(), LoaderError> {
        let address = region.address;
        let last = region
            .size
            .max(1)
            .checked_sub(1)
            .and_then(|extent| address.checked_add(extent))
            .ok_or_else(|| LoaderError::address_overflow(address))?;
        let range = address..=last;
        let overlaps = self.covered.intersects_range(range.clone());
        let source = region.source();
        let is_segment = source.is_some_and(ElfRegionSource::is_segment);
        if source.is_some_and(ElfRegionSource::is_header) {
            let overlay = self.next_overlay_space();
            let bank = self.bank_layout.allocate_overlay(range.clone());
            let placement = self.push_placement(&region, overlay, 0u64);
            self.placements[placement].bank = bank;
            self.bank_layout
                .route_region(source.expect("header source"), bank);
            self.covered.insert_range(range);
            return Ok(());
        }
        let backing_offset = address
            .checked_sub(self.bank_base)
            .ok_or_else(|| LoaderError::address_overflow(address))?;

        let file_delta = region
            .file_offset
            .map(|off| off.wrapping_sub(address.offset()));

        let conflicts = file_delta
            .and_then(|delta| {
                is_segment.then(|| {
                    self.conflicting_base_regions(
                        ElfRegionSourceKind::Segment,
                        address,
                        last,
                        delta,
                    )
                })
            })
            .unwrap_or_default();

        let placement = if !conflicts.is_empty() {
            for index in conflicts {
                self.demote_region(index);
            }
            Some(self.push_placement(&region, self.base_space, backing_offset))
        } else if overlaps {
            self.place_overlapping_region(&region, backing_offset, last, file_delta)
        } else {
            Some(self.push_placement(&region, self.base_space, backing_offset))
        };

        self.covered.insert_range(range);

        let Some(((placement, source), file_delta)) = placement.zip(source).zip(file_delta) else {
            return Ok(());
        };

        self.placed_regions.push(ElfPlacedRegion::new(
            address, last, file_delta, placement, source,
        ));

        Ok(())
    }

    fn demote_region(&mut self, placed_index: usize) {
        let placed = &self.placed_regions[placed_index];
        let placement = placed.placement();
        let start = placed.start();
        let last = placed.last();
        let source = placed.source();

        if self.placements[placement].space() != self.base_space {
            return;
        }

        let overlay = self.next_overlay_space();
        let bank = self.bank_layout.allocate_overlay(start..=last);

        let displaced = &mut self.placements[placement];
        displaced.address = ImageAddress::new(overlay, start);
        displaced.bank = bank;
        displaced.backing_offset = RawAddress::from(0u64);

        self.bank_layout.route_region(source, bank);
    }

    fn into_parts(self) -> (Vec<ElfImageSegment>, ImageSpaces, ElfBankLayout) {
        (self.placements, self.spaces, self.bank_layout)
    }
}

struct ElfImageSegments<'a> {
    segments: slice::Iter<'a, ElfImageSegment>,
    mapping_hints: &'a BTreeMap<RawAddress, ContextHint>,
    image_symbols: &'a TransientSymbolTable<ImageAddress>,
}

impl<'a> ElfImageSegments<'a> {
    fn new(
        segments: &'a [ElfImageSegment],
        image_symbols: &'a TransientSymbolTable<ImageAddress>,
        mapping_hints: &'a BTreeMap<RawAddress, ContextHint>,
    ) -> Self {
        Self {
            segments: segments.iter(),
            mapping_hints,
            image_symbols,
        }
    }

    fn image_segment(&self, segment: &'a ElfImageSegment) -> ImageSegment<'a> {
        let seg_start = segment.address.offset();
        let seg_last = seg_start.checked_add(segment.size.saturating_sub(1));

        let (mapping_hints, function_hints) = seg_last
            .map(|seg_last| {
                let mapping_hints = self
                    .mapping_hints
                    .range(seg_start..=seg_last)
                    .map(|(addr, hint)| (*addr, hint.clone()))
                    .collect::<BTreeMap<RawAddress, ContextHint>>();

                let space = segment.address.space();
                let function_hints = self
                    .image_symbols
                    .range_by_address(
                        ImageAddress::new(space, seg_start)..=ImageAddress::new(space, seg_last),
                    )
                    .filter(|(_, entry)| {
                        entry
                            .properties()
                            .contains(SymbolProperties::FUNCTION | SymbolProperties::EXTERN)
                    })
                    .map(|(_, entry)| entry.address().offset())
                    .collect::<BTreeSet<RawAddress>>();

                (mapping_hints, function_hints)
            })
            .unwrap_or_default();

        ImageSegment::new(
            segment.name.as_str(),
            segment.address,
            segment.size,
            segment.properties,
        )
        .with_backing(ImageBacking::new(segment.bank, segment.backing_offset))
        .with_provenance(segment.provenance)
        .with_mapping_hints(mapping_hints)
        .with_function_hints(function_hints)
    }
}

impl<'a> FallibleIterator for ElfImageSegments<'a> {
    type Error = LoaderError;
    type Item = ImageSegment<'a>;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        let Some(segment) = self.segments.next() else {
            return Ok(None);
        };
        Ok(Some(self.image_segment(segment)))
    }
}

struct RawElfSymbol {
    address: RawAddress,
    symbol: Symbol,
    properties: SymbolProperties,
}

struct ElfSymbolLayout {
    bounds: RangeInclusive<RawAddress>,
    mapping_hints: BTreeMap<RawAddress, ContextHint>,
    symbols: BTreeMap<SymbolIndex, RawElfSymbol>,
    sections: ElfSectionMap,
    external_thunks: ExternalThunkLayout,
}

impl ElfSymbolLayout {
    fn from_elf<'a>(
        elf: &'a impl Object<'a>,
        arch: &Arch,
        base_addr: RawAddress,
        preferred_base: RawAddress,
        config: ElfLoaderProperties,
    ) -> Result<Self, LoaderError> {
        let is_object = elf.kind() == ObjectKind::Relocatable;
        let addr_size = arch.language().address_size();
        let address_upper_bound = RawAddress::from(arch.language().address_upper_bound());

        let addr_align = arch.language().address_alignment().max(addr_size);

        let mut sections = ElfSectionMap::new();
        let mut mapping_hints = BTreeMap::new();

        let mut min_addr = base_addr;
        let mut max_addr = base_addr;

        let external_base = if is_object {
            let base = if config.preserve_relocatable_section_addresses() {
                Self::place_object_sections_preserving_addresses(
                    elf,
                    base_addr,
                    address_upper_bound,
                    &mut sections,
                    &config,
                )?
            } else {
                Self::place_object_sections(elf, base_addr, &mut sections, &config)?
            };

            max_addr = base;
            base
        } else {
            for (addr, size) in elf
                .sections()
                .map(|sect| (sect.address(), sect.size()))
                .chain(elf.segments().map(|segm| (segm.address(), segm.size())))
                .filter(|(addr, size)| *size != 0 && *addr >= preferred_base.offset())
            {
                let curr_min = base_addr
                    .checked_add(addr - preferred_base.offset())
                    .ok_or_else(|| LoaderError::address_overflow(base_addr))?;

                let curr_max = curr_min
                    .checked_add(size)
                    .ok_or_else(|| LoaderError::address_overflow(base_addr))?;

                max_addr = max_addr.max(curr_max);
                min_addr = min_addr.min(curr_min);
            }
            max_addr
                .checked_add(addr_size as u64)
                .ok_or_else(|| LoaderError::address_overflow(base_addr))?
        };

        let aligned_external_base = external_base.align(addr_align);

        if aligned_external_base < external_base {
            return Err(LoaderError::address_overflow(base_addr));
        }

        let mut symbols = BTreeMap::<SymbolIndex, RawElfSymbol>::new();

        for (section, symbol) in elf
            .symbols()
            .filter_map(|sym| sym.section_index().map(|idx| (idx, sym)))
        {
            let address = if is_object {
                let Some(section_start) = sections.get(section.0) else {
                    continue;
                };
                RawAddress::from(symbol.address()) + section_start
            } else {
                RawAddress::from(symbol.address()) - preferred_base + base_addr
            };

            tracing::trace!(
                "symbol {} in section {section:?} at {address}",
                symbol.name().ok().unwrap_or("<unnamed>"),
            );

            // NOTE: here we deal with mapping symbols, which are used to indicate code/data
            // boundaries, etc. and do not need to be added to the symbol table.
            if let Ok(name) = symbol.name()
                && let Some(context) = arch.resolve_mapping_symbol(name)
            {
                tracing::trace!(
                    "symbol {name} in section {section:?} at {address} is a mapping symbol"
                );
                mapping_hints.insert(address, context);
                continue;
            }

            let SymbolFlags::Elf { st_info, .. } = symbol.flags() else {
                continue;
            };

            let st_bind = st_info >> 4;
            let st_type = st_info & 0x0f;

            let is_visible = st_bind == STB_GLOBAL || st_bind == STB_WEAK;

            let is_import = is_visible && symbol.address() == 0;
            let is_export = is_visible && symbol.address() != 0;

            let kind = if [STT_FUNC, STT_GNU_IFUNC].contains(&st_type) {
                SymbolProperties::FUNCTION
            } else if [STT_COMMON, STT_OBJECT, STT_TLS, STT_GNU_UNIQUE].contains(&st_type) {
                SymbolProperties::DATA
            } else {
                tracing::debug!(
                    "symbol {address} is not a function or data: {st_bind:x}/{st_type:x}"
                );
                SymbolProperties::NONE
            };

            let mut properties = kind;

            if is_import && (!is_object || st_type == STT_NOTYPE) {
                properties |= SymbolProperties::EXTERN;
            } else if is_export {
                properties |= SymbolProperties::EXPORT | SymbolProperties::LOCAL;
            } else {
                properties |= SymbolProperties::LOCAL;
            }

            symbols.insert(
                SymbolIndex::new(ELF_SYMTAB_SELECTOR, symbol.index().0),
                RawElfSymbol {
                    address,
                    symbol: symbol.name().ok().unwrap_or_default().into(),
                    properties,
                },
            );
        }

        let (syms, selector) = if is_object {
            (elf.symbols(), ELF_SYMTAB_SELECTOR)
        } else {
            (elf.dynamic_symbols(), ELF_DYNSYM_SELECTOR)
        };

        // NOTE: this template is used to create a stub for the external symbols, such that
        // if we were to consider the external address as a function, and call to it, we would
        // hit valid code, and return.

        let mut external_thunks = ExternalThunkLayout::new(
            aligned_external_base,
            addr_align,
            arch.external_thunk_template(),
        );

        for (index, sym, properties) in syms.filter_map(|sym| {
            let index = sym.index().0;

            let SymbolFlags::Elf { st_info, .. } = sym.flags() else {
                return None;
            };

            let st_bind = st_info >> 4;
            let st_type = st_info & 0x0f;

            let is_visible = st_bind == STB_GLOBAL || st_bind == STB_WEAK;

            let is_import = is_visible && sym.address() == 0;
            let is_export = is_visible && sym.address() != 0;

            let kind = if [STT_FUNC, STT_GNU_IFUNC].contains(&st_type) {
                SymbolProperties::FUNCTION
            } else if [STT_COMMON, STT_OBJECT, STT_TLS, STT_GNU_UNIQUE].contains(&st_type) {
                SymbolProperties::DATA
            } else {
                SymbolProperties::NONE
            };

            if is_import && (!is_object || st_type == STT_NOTYPE) {
                Some((index, sym, kind | SymbolProperties::EXTERN))
            } else if is_export {
                Some((
                    index,
                    sym,
                    kind | SymbolProperties::LOCAL | SymbolProperties::EXPORT,
                ))
            } else {
                tracing::debug!(
                    "skipping symbol {} (bind: {st_bind}, type: {st_type}, addr: {:#x})",
                    sym.name().ok().unwrap_or("<unnamed>"),
                    sym.address(),
                );
                None
            }
        }) {
            let address = if properties.is_extern() {
                external_thunks
                    .allocate()
                    .ok_or_else(|| LoaderError::address_overflow(base_addr))?
            } else if is_object {
                let Some(section_start) = sym
                    .section_index()
                    .and_then(|section| sections.get(section.0))
                else {
                    continue;
                };
                section_start + sym.address()
            } else {
                (base_addr - preferred_base) + sym.address()
            };
            let symbol = sym.name().ok().unwrap_or_default().into();

            symbols.insert(
                SymbolIndex::new(selector, index),
                RawElfSymbol {
                    address,
                    symbol,
                    properties,
                },
            );
        }

        let max_addr = external_thunks.last().unwrap_or(max_addr);
        let bounds = min_addr..=max_addr;

        Ok(Self {
            bounds,
            mapping_hints,
            symbols,
            sections,
            external_thunks,
        })
    }

    fn is_placeable_object_section<'a>(
        sect: &impl ObjectSection<'a>,
        config: &ElfLoaderProperties,
    ) -> bool {
        let SectionFlags::Elf { sh_flags } = sect.flags() else {
            return false;
        };

        if (sh_flags as u32 & SHF_ALLOC) != SHF_ALLOC {
            return false;
        }

        !(config.skip_note_sections() && sect.kind() == SectionKind::Note)
    }

    fn place_object_sections<'a>(
        elf: &'a impl Object<'a>,
        base_addr: RawAddress,
        sections: &mut ElfSectionMap,
        config: &ElfLoaderProperties,
    ) -> Result<RawAddress, LoaderError> {
        let mut base = base_addr;
        for sect in elf.sections() {
            if !Self::is_placeable_object_section(&sect, config) {
                continue;
            }

            let aligned_start = base.align(sect.align().max(1) as usize);

            if aligned_start < base {
                tracing::debug!("section start {aligned_start:#x} overflow; skipping section");
                continue;
            }

            sections.insert(sect.index().0, aligned_start);

            base = aligned_start
                .checked_add(sect.size().max(1))
                .ok_or_else(|| LoaderError::address_overflow(base_addr))?;
        }
        Ok(base)
    }

    fn place_object_sections_preserving_addresses<'a>(
        elf: &'a impl Object<'a>,
        base_addr: RawAddress,
        address_upper_bound: RawAddress,
        sections: &mut ElfSectionMap,
        config: &ElfLoaderProperties,
    ) -> Result<RawAddress, LoaderError> {
        let mut pinned_end = RawAddress::zero();
        for sect in elf.sections() {
            if !Self::is_placeable_object_section(&sect, config) || sect.size() == 0 {
                continue;
            }

            if sect.address() != 0 {
                let end = RawAddress::from(sect.address())
                    .checked_add(sect.size())
                    .ok_or_else(|| LoaderError::address_overflow(base_addr))?;
                pinned_end = pinned_end.max(end);
            }
        }

        if pinned_end.offset() > address_upper_bound.offset() >> 1 {
            pinned_end = RawAddress::zero();
        }

        let mut base = base_addr
            .checked_add(pinned_end)
            .ok_or_else(|| LoaderError::address_overflow(base_addr))?;

        for sect in elf.sections() {
            if !Self::is_placeable_object_section(&sect, config) || sect.size() == 0 {
                continue;
            }

            if sect.address() != 0 {
                let pinned_start = base_addr
                    .checked_add(sect.address())
                    .ok_or_else(|| LoaderError::address_overflow(base_addr))?;
                sections.insert(sect.index().0, pinned_start);
                continue;
            }

            let aligned_start = base.align(sect.align().max(1) as usize);

            if aligned_start < base {
                tracing::debug!("section start {aligned_start:#x} overflow; skipping section");
                continue;
            }

            sections.insert(sect.index().0, aligned_start);

            base = aligned_start
                .checked_add(sect.size())
                .ok_or_else(|| LoaderError::address_overflow(base_addr))?;
        }

        Ok(base.max(
            base_addr
                .checked_add(pinned_end)
                .ok_or_else(|| LoaderError::address_overflow(base_addr))?,
        ))
    }
}

fn elf_section_properties<'a>(
    sect: &impl ObjectSection<'a>,
    _config: &ElfLoaderProperties,
) -> SegmentProperties {
    let SectionFlags::Elf { sh_flags } = sect.flags() else {
        // NOTE: we could probably panic here
        return SegmentProperties::empty();
    };

    let sh_flags = sh_flags as u32;

    let mut props = SegmentProperties::PERM_READ;

    if sh_flags & SHF_WRITE == SHF_WRITE {
        props.insert(SegmentProperties::PERM_WRITE);
    }

    if sh_flags & SHF_EXECINSTR == SHF_EXECINSTR {
        props.insert(SegmentProperties::PERM_EXECUTE);
    }

    if matches!(sect.file_range(), None | Some((_, 0))) {
        props.insert(SegmentProperties::UNINITIALISED);
    }

    props
}

fn elf_segment_properties<'a>(
    segm: &impl ObjectSegment<'a>,
    config: &ElfLoaderProperties,
) -> SegmentProperties {
    let SegmentFlags::Elf { p_flags } = segm.flags() else {
        // NOTE: we could probably panic here
        return SegmentProperties::empty();
    };

    let mut props = SegmentProperties::empty();

    if p_flags & PF_R == PF_R {
        props.insert(SegmentProperties::PERM_READ);
    }

    if p_flags & PF_W == PF_W {
        props.insert(SegmentProperties::PERM_WRITE);
    }

    if p_flags & PF_X == PF_X && !config.ignore_segment_exec_permission() {
        props.insert(SegmentProperties::PERM_EXECUTE);
    }

    if segm.file_range().1 == 0 {
        props.insert(SegmentProperties::UNINITIALISED);
    }

    props
}

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub(crate) struct ElfLoaderProperties: u8 {
        // user configuration
        const OVERRIDE_SEGMENT_PERMISSIONS = 0b0000_0001;
        const SKIP_NOTE_SECTIONS = 0b0000_0010;
        const PRESERVE_RELOCATABLE_SECTION_ADDRESSES = 0b0000_0100;
        const LOAD_HEADERS = 0b0000_1000;

        // loader state tracking
        const HAS_LOADED_SECTIONS = 0b0001_0000;
        const IS_OBJECT = 0b0010_0000;

        // derived configuration
        const IGNORE_SEGMENT_EXEC_PERMISSION =
            Self::OVERRIDE_SEGMENT_PERMISSIONS.bits() | Self::HAS_LOADED_SECTIONS.bits();
    }
}

impl ElfLoaderProperties {
    pub(crate) fn new(attrs: &AttributeMap) -> Self {
        let mut config = Self::empty();

        if attrs
            .get_attr::<bool>(ATTRIBUTE_OVERRIDE_SEGMENT_PERMISSIONS)
            .unwrap_or_default()
        {
            config.insert(Self::OVERRIDE_SEGMENT_PERMISSIONS);
        }

        if attrs
            .get_attr::<bool>(ATTRIBUTE_SKIP_NOTE_SECTIONS)
            .unwrap_or_default()
        {
            config.insert(Self::SKIP_NOTE_SECTIONS);
        }

        if attrs
            .get_attr::<bool>(ATTRIBUTE_PRESERVE_RELOCATABLE_SECTION_ADDRESSES)
            .unwrap_or_default()
        {
            config.insert(Self::PRESERVE_RELOCATABLE_SECTION_ADDRESSES);
        }

        if attrs
            .get_attr::<bool>(ATTRIBUTE_LOAD_HEADERS)
            .unwrap_or_default()
        {
            config.insert(Self::LOAD_HEADERS);
        }

        config
    }

    pub(crate) fn is_object(&self) -> bool {
        self.contains(Self::IS_OBJECT)
    }

    pub(crate) fn skip_note_sections(&self) -> bool {
        self.contains(Self::SKIP_NOTE_SECTIONS)
    }

    pub(crate) fn preserve_relocatable_section_addresses(&self) -> bool {
        self.contains(Self::PRESERVE_RELOCATABLE_SECTION_ADDRESSES)
    }

    pub(crate) fn ignore_segment_exec_permission(&self) -> bool {
        self.contains(Self::IGNORE_SEGMENT_EXEC_PERMISSION)
    }

    pub(crate) fn load_headers(&self) -> bool {
        self.contains(Self::LOAD_HEADERS)
    }
}

struct ElfImageContext<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    elf: &'file ElfFile<'data, Elf, R>,
    arch: &'file Arch,
    symbols: &'file TransientSymbolTable<ImageAddress>,
    sections: &'file ElfSectionMap,
    external_thunks: &'file ExternalThunkLayout,
    region_bank: &'file ElfRegionBankMap,
    config: ElfLoaderProperties,
}

impl<'data, 'file, Elf, R> ElfImageContext<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn new(
        elf: &'file ElfFile<'data, Elf, R>,
        arch: &'file Arch,
        symbols: &'file TransientSymbolTable<ImageAddress>,
        sections: &'file ElfSectionMap,
        external_thunks: &'file ExternalThunkLayout,
        region_bank: &'file ElfRegionBankMap,
        mut config: ElfLoaderProperties,
    ) -> Self {
        if elf.kind() == ObjectKind::Relocatable {
            config.insert(ElfLoaderProperties::IS_OBJECT);
        }

        Self {
            elf,
            arch,
            symbols,
            sections,
            external_thunks,
            region_bank,
            config,
        }
    }

    fn elf(&self) -> &'file ElfFile<'data, Elf, R> {
        self.elf
    }

    fn arch(&self) -> &'file Arch {
        self.arch
    }

    fn symbols(&self) -> &'file TransientSymbolTable<ImageAddress> {
        self.symbols
    }

    fn sections(&self) -> &'file ElfSectionMap {
        self.sections
    }

    fn external_thunks(&self) -> &'file ExternalThunkLayout {
        self.external_thunks
    }

    fn region_bank(&self) -> &'file ElfRegionBankMap {
        self.region_bank
    }

    fn config(&self) -> &ElfLoaderProperties {
        &self.config
    }
}

pub(crate) struct ElfImageSegmentContents<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    context: ElfImageContext<'data, 'file, Elf, R>,
    segms: ElfSegmentIterator<'data, 'file, Elf, R>,
    sects: ElfSectionIterator<'data, 'file, Elf, R>,
    headers: ElfHeaderRegions<'data>,
    covered: ElfCoveredRegions,
    current_base: RawAddress,
    preferred_base: RawAddress,
    external_thunks_pending: bool,
    segment_ordinal: usize,
}

impl<'data, 'file, Elf, R> ElfImageSegmentContents<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn new(
        context: ElfImageContext<'data, 'file, Elf, R>,
        base: RawAddress,
        preferred_base: RawAddress,
    ) -> Result<Self, LoaderError> {
        let elf = context.elf();

        Ok(Self {
            context,
            sects: elf.sections(),
            segms: elf.segments(),
            headers: ElfHeaderRegions::new(elf, base, preferred_base)?,
            covered: ElfCoveredRegions::new(),
            current_base: base,
            preferred_base,
            external_thunks_pending: true,
            segment_ordinal: 0,
        })
    }

    pub(crate) fn external_thunk_contents(&mut self) -> Option<ImageSegmentContents<'data>> {
        if !self.external_thunks_pending {
            return None;
        }
        self.external_thunks_pending = false;

        let external_thunks = self.context.external_thunks();
        if external_thunks.is_empty() {
            return None;
        }
        let external_size = external_thunks.size();
        let external_padding =
            external_thunks.aligned_template_size() - external_thunks.template().size();

        let address = external_thunks.start();
        let last_address = external_thunks.last().expect("not empty");

        let mut contents = Vec::with_capacity(external_size);

        let function_offsets = self
            .context
            .symbols()
            .iter()
            .filter_map(|(_, sym)| {
                if sym
                    .properties()
                    .contains(SymbolProperties::FUNCTION | SymbolProperties::EXTERN)
                {
                    Some(sym.address().offset())
                } else {
                    None
                }
            })
            .collect::<BTreeSet<RawAddress>>();

        for addr in external_thunks.iter() {
            if function_offsets.contains(&RawAddress::from(addr.offset())) {
                contents.extend_from_slice(external_thunks.template().bytes());
                contents.resize(contents.len() + external_padding, 0);
            } else {
                contents.resize(contents.len() + external_thunks.aligned_template_size(), 0);
            }
        }

        let external_range = address..=last_address;
        self.covered
            .insert_range(ImageBankHandle::default(), external_range);

        let mut bytes = ImageSegmentContents::new(
            external_thunks.start(),
            self.context.arch().endian(),
            Cow::Owned(contents),
        );
        for offset in function_offsets {
            bytes.add_function_hint(offset);
        }

        Some(bytes)
    }

    pub(crate) fn header_segment(
        &mut self,
    ) -> Result<Option<ImageSegmentContents<'data>>, LoaderError> {
        if !self.context.config().load_headers() {
            return Ok(None);
        }

        let Some(header) = self.headers.next() else {
            return Ok(None);
        };
        let last_address = header
            .address
            .checked_add(header.size().wrapping_sub(1))
            .ok_or_else(|| LoaderError::address_overflow(header.address))?;
        let bank = self
            .context
            .region_bank()
            .bank_for(header.source)
            .unwrap_or_default();
        self.covered
            .insert_range(bank, header.address..=last_address);

        Ok(Some(ImageSegmentContents::new_sparse_in_bank(
            bank,
            header.address,
            self.context.arch().endian(),
            header.data(),
            header.size(),
        )))
    }

    pub(crate) fn next_unlinked(
        &mut self,
    ) -> Result<Option<ImageSegmentContents<'data>>, LoaderError> {
        if let Some(header) = self.header_segment()? {
            return Ok(Some(header));
        }

        for sect in self.sects.by_ref() {
            let Some(address) = self.context.sections().get(sect.index().0) else {
                continue;
            };

            let span = sect.size().max(1);
            let last_address = address
                .checked_add(span.wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(address))?;

            tracing::trace!("processing section {address}-{last_address}");

            let data = sect.data().unwrap_or_default();
            let vrange = address..=last_address;

            tracing::trace!("loading section {address}-{last_address}");

            let emit = (data.len() as u64).min(span) as usize;

            let bank = self
                .context
                .region_bank()
                .bank_for(ElfRegionSource::section(sect.index().0))
                .unwrap_or_default();

            let mut bytes = ImageSegmentContents::new_sparse_in_bank(
                bank,
                address,
                self.context.arch().endian(),
                &data[..emit],
                span,
            );

            self.covered.insert_range(bank, vrange);

            let relocator = ElfSegmentRelocator::new(
                self.context.elf(),
                self.context.arch(),
                address,
                self.context.symbols(),
                self.context.config().is_object(),
            );

            relocator.apply(address, &mut bytes, &sect)?;

            return Ok(Some(bytes));
        }

        Ok(self.external_thunk_contents())
    }

    pub(crate) fn next_linked_section(
        &mut self,
    ) -> Result<Option<ImageSegmentContents<'data>>, LoaderError> {
        let relocator = ElfSegmentRelocator::new(
            self.context.elf(),
            self.context.arch(),
            self.current_base - self.preferred_base,
            self.context.symbols(),
            self.context.config().is_object(),
        );

        for sect in self.sects.by_ref() {
            let SectionFlags::Elf { sh_flags } = sect.flags() else {
                continue;
            };

            let size = sect.size();

            if size == 0 || (sh_flags as u32 & SHF_ALLOC) != SHF_ALLOC {
                continue;
            }

            if (sh_flags as u32 & SHF_TLS) == SHF_TLS {
                tracing::debug!(
                    "skipping TLS section {}",
                    sect.name().unwrap_or("<unnamed>")
                );
                continue;
            }

            let address = (self.current_base - self.preferred_base) + sect.address();

            let last_address = address
                .checked_add(size.wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(address))?;

            let vrange = address..=last_address;
            let bank = self
                .context
                .region_bank()
                .bank_for(ElfRegionSource::section(sect.index().0))
                .unwrap_or_default();
            if self.covered.intersects_range(bank, vrange.clone()) {
                tracing::debug!("section {address}-{last_address} already covered; skipping");
                continue;
            }

            tracing::trace!("processing section {address}-{last_address}");

            let data = sect.data().unwrap_or_default();

            tracing::trace!("loading section {address}-{last_address}");

            let emit = (data.len() as u64).min(sect.size()) as usize;

            let mut bytes = ImageSegmentContents::new_sparse_in_bank(
                bank,
                address,
                self.context.arch().endian(),
                &data[..emit],
                sect.size(),
            );

            self.covered.insert_range(bank, vrange);

            relocator.apply(address, &mut bytes, &sect)?;

            return Ok(Some(bytes));
        }

        Ok(None)
    }

    pub(crate) fn next_linked_segment(
        &mut self,
    ) -> Result<Option<ImageSegmentContents<'data>>, LoaderError> {
        let relocator = ElfSegmentRelocator::new(
            self.context.elf(),
            self.context.arch(),
            self.current_base - self.preferred_base,
            self.context.symbols(),
            self.context.config().is_object(),
        );

        for segm in self.segms.by_ref() {
            let size = segm.size();

            if segm.size() == 0 {
                continue;
            }

            let ordinal = self.segment_ordinal;
            self.segment_ordinal += 1;

            let address = (self.current_base - self.preferred_base) + segm.address();

            let last_address = address
                .checked_add(size.wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(address))?;

            let vrange = address..=last_address;
            let bank = self
                .context
                .region_bank()
                .bank_for(ElfRegionSource::segment(ordinal))
                .unwrap_or_default();
            self.covered.insert_range(bank, vrange);

            tracing::trace!("processing segment {address}-{last_address}");

            let data = segm.data().unwrap_or_default();

            tracing::trace!("loading segment {address}-{last_address}");

            let emit = data.len().min(size as usize);

            let mut bytes = ImageSegmentContents::new_sparse_in_bank(
                bank,
                address,
                self.context.arch().endian(),
                &data[..emit],
                size,
            );

            relocator.apply_dynamic_relocations(address, &mut bytes)?;

            return Ok(Some(bytes));
        }

        Ok(None)
    }

    pub(crate) fn next_linked(
        &mut self,
    ) -> Result<Option<ImageSegmentContents<'data>>, LoaderError> {
        if let Some(header) = self.header_segment()? {
            return Ok(Some(header));
        }

        if let Some(v) = self.next_linked_segment()? {
            return Ok(Some(v));
        }

        if let Some(v) = self.next_linked_section()? {
            return Ok(Some(v));
        }

        Ok(self.external_thunk_contents())
    }
}

impl<'data, 'file, Elf, R> FallibleIterator for ElfImageSegmentContents<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    type Error = LoaderError;
    type Item = ImageSegmentContents<'data>;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.context.config().is_object() {
            self.next_unlinked()
        } else {
            self.next_linked()
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<'a> LoadableFromBytes<'a> for Elf<'a> {
    fn from_bytes_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized,
    {
        Self::new_with(data, attributes)
    }
}

impl LoadableFromFile for Elf<'_> {
    fn from_file_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized,
    {
        let path = path.as_ref();

        let mut loaded = Self::new_with(BytesOrMapping::from_file(path)?, attributes)?;

        loaded.path = Some(path.display().to_string());

        Ok(loaded)
    }
}

impl Loadable for Elf<'_> {
    fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    fn metadata(&self) -> &LoadableMetadata {
        self.metadata.get_or_init(|| {
            LoadableMetadata::new_with(
                self.object.borrow_data(),
                self.path.clone(),
                format!("Fugue v{} ELF Loader", env!("CARGO_PKG_VERSION")),
            )
        })
    }

    fn architecture(&self) -> Arch {
        self.architecture.clone()
    }

    fn platform(&self) -> Platform {
        self.architecture
            .platform()
            .with_compiler_spec_id("gcc")
            .with_format(Format::Elf)
            .with_os(self.operating_system())
    }

    fn image_symbols(&self) -> Option<&TransientSymbolTable<ImageAddress>> {
        Some(&self.image_symbols)
    }

    fn entry_point(&self) -> Option<ImageAddress> {
        self.entry
    }

    fn image_segments<'b>(
        &'b self,
    ) -> impl FallibleIterator<Item = ImageSegment<'b>, Error = LoaderError> + 'b {
        Box::new(ElfImageSegments::new(
            &self.segments,
            &self.image_symbols,
            &self.mapping_hints,
        )) as ImageSegmentIterator<'b>
    }

    fn image_layout(&self) -> &ImageLayout {
        &self.layout
    }

    fn image_contents<'b>(
        &'b self,
    ) -> impl FallibleIterator<Item = ImageSegmentContents<'b>, Error = LoaderError> + 'b {
        let view = self.object.borrow_view();
        let props = ElfLoaderProperties::new(self.attributes());

        with_elf!(
            view,
            elf | {
                let context = ElfImageContext::new(
                    elf,
                    &self.architecture,
                    &self.image_symbols,
                    &self.sections,
                    &self.external_thunks,
                    &self.region_bank,
                    props,
                );
                match ElfImageSegmentContents::new(context, self.base, self.preferred_base) {
                    Ok(contents) => Box::new(contents) as ImageSegmentContentsIterator<'b>,
                    Err(err) => Box::new(fallible_iterator::once_err(err))
                        as ImageSegmentContentsIterator<'b>,
                }
            }
        )
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use fallible_iterator::FallibleIterator;
    use object::elf::{R_ARM_JUMP_SLOT, R_ARM_RELATIVE};
    use object::{Object, ObjectSymbol, RelocationFlags, RelocationTarget};

    use super::{ATTRIBUTE_LOAD_HEADERS, ELF_DYNSYM_SELECTOR, Elf, ElfFileRepr};
    use crate::attributes;
    use crate::ir::{Address, RawAddress, RawAddressRangeSet, SymbolIndex};
    use crate::loader::{
        ImageBankHandle, ImageSegmentContents, ImageSpaceHandle, ImageSpaceKind, Loadable,
        LoadableFromFile, LoadableMetadata,
    };
    use crate::storage::segments::{InMemorySegmentStorage, SegmentStorage};
    use crate::types::BytesOrMapping;
    use crate::types::attributes::{ATTRIBUTE_IMAGE_BASE, AttributeMap};

    struct Placement {
        address: Address,
    }

    fn load_image_bytes(
        loadable: &impl Loadable,
    ) -> Result<Vec<ImageSegmentContents<'static>>, Box<dyn std::error::Error>> {
        let mut segments = Vec::new();
        let mut image_segments = loadable.image_segments();

        while let Some(segment) = image_segments.next()? {
            if let Some(backing) = segment.backing() {
                segments.push((segment.address(), backing, segment.size()));
            }
        }

        let bank = ImageBankHandle::default();
        let bank_base = loadable
            .image_layout()
            .banks()
            .iter()
            .find(|entry| entry.handle() == bank)
            .map(|entry| *entry.range().start())
            .expect("default bank");

        let mut contents = loadable.image_contents();
        let mut loaded = Vec::new();

        while let Some(segment) = contents.next()? {
            for write in segment.into_writes(bank_base)? {
                let placement = segments
                    .iter()
                    .find_map(|(address, backing, size)| {
                        if backing.bank() != write.bank() {
                            return None;
                        }

                        let start = backing.offset();
                        let end = start.checked_add(*size)?;

                        if write.offset() < start || write.offset() >= end {
                            return None;
                        }

                        let delta = write.offset() - start;

                        Some(Placement {
                            address: Address::in_default_space(address.offset() + delta),
                        })
                    })
                    .unwrap_or_else(|| Placement {
                        address: write.offset().into(),
                    });

                loaded.push(ImageSegmentContents::new(
                    placement.address,
                    loadable.architecture().endian(),
                    write.bytes().to_owned(),
                ));
            }
        }

        Ok(loaded)
    }

    struct CapturedImageWrite {
        offset: RawAddress,
        bytes: Vec<u8>,
    }

    fn image_writes(
        loadable: &impl Loadable,
    ) -> Result<Vec<CapturedImageWrite>, Box<dyn std::error::Error>> {
        let bank = ImageBankHandle::default();
        let bank_base = loadable
            .image_layout()
            .banks()
            .iter()
            .find(|entry| entry.handle() == bank)
            .map(|entry| *entry.range().start())
            .expect("default bank");

        let mut contents = loadable.image_contents();
        let mut writes = Vec::new();
        while let Some(segment) = contents.next()? {
            for write in segment.into_writes(bank_base)? {
                writes.push(CapturedImageWrite {
                    offset: write.offset(),
                    bytes: write.bytes().to_owned(),
                });
            }
        }
        Ok(writes)
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_exe() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let elf = Elf::new(BytesOrMapping::from_file("tests/ls.elf")?)?;
            let mut segments = elf.image_segments();
            while let Some(segment) = segments.next()? {
                tracing::info!(
                    "{}+{:#x} ({})",
                    segment.address().offset(),
                    segment.size(),
                    segment.name()
                );
            }
            tracing::info!("architecture: {}", elf.architecture());

            for (_, sym) in elf.image_symbols().iter() {
                tracing::info!("symbol {sym}");
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_headers_default_disabled() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new(BytesOrMapping::from_file("tests/ls.elf")?)?;
        let mut segments = elf.image_segments();
        while let Some(segment) = segments.next()? {
            assert!(
                !segment.name().starts_with("_elf"),
                "unexpected default ELF header segment {}",
                segment.name()
            );
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_headers_enabled() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new_with(
            BytesOrMapping::from_file("tests/ls.elf")?,
            attributes![ATTRIBUTE_LOAD_HEADERS => true],
        )?;

        let mut header_addresses = BTreeSet::new();
        let mut segments = elf.image_segments();
        while let Some(segment) = segments.next()? {
            if segment.name().starts_with("_elf") {
                header_addresses.insert(segment.address().offset());
                assert!(segment.size() > 0);
            }
        }
        assert!(
            header_addresses.contains(&RawAddress::zero()),
            "expected ELF file header segment"
        );

        let mut saw_contents = false;
        let mut contents = elf.image_contents();
        while let Some(segment) = contents.next()? {
            if header_addresses.contains(&segment.address()) {
                saw_contents = true;
                assert!(!segment.is_empty());
            }
        }
        assert!(saw_contents, "expected ELF header contents");
        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_dyn() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let elf = Elf::new(BytesOrMapping::from_file("tests/libipmi.so")?)?;
            let mut segments = elf.image_segments();
            while let Some(segment) = segments.next()? {
                tracing::info!(
                    "{}+{:#x} ({})",
                    segment.address().offset(),
                    segment.size(),
                    segment.name()
                );
            }
            tracing::info!("architecture: {}", elf.architecture());

            for (_, sym) in elf.image_symbols().iter() {
                tracing::info!("symbol {sym}");
            }

            for (addr, hint) in elf.mapping_hints() {
                tracing::info!("mapping hint {addr}: {hint}");
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_rel() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let elf = Elf::new(BytesOrMapping::from_file("tests/liblzma_la-crc64-fast.o")?)?;
            let mut segments = elf.image_segments();
            while let Some(segment) = segments.next()? {
                tracing::info!(
                    "{}+{:#x} ({})",
                    segment.address().offset(),
                    segment.size(),
                    segment.name()
                );
            }
            tracing::info!("architecture: {}", elf.architecture());

            for (_, sym) in elf.image_symbols().iter() {
                tracing::info!("symbol {sym}");
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_ko_rel() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let elf = Elf::new(BytesOrMapping::from_file("tests/inv-icm42600.ko")?)?;
            let mut segments = elf.image_segments();
            while let Some(segment) = segments.next()? {
                tracing::info!(
                    "{}+{:#x} ({})",
                    segment.address().offset(),
                    segment.size(),
                    segment.name()
                );
            }
            tracing::info!("architecture: {}", elf.architecture());

            for (_, sym) in elf.image_symbols().iter() {
                tracing::info!("symbol {sym}");
            }

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_rebased_dynamic_relocations() -> Result<(), Box<dyn std::error::Error>> {
        let mut attributes = AttributeMap::new();
        let image_base = RawAddress::new(0x4000_0000u64);

        attributes.set_attr(ATTRIBUTE_IMAGE_BASE, image_base);

        let elf = Elf::new_with(BytesOrMapping::from_file("tests/ls.elf")?, attributes)?;

        let image_base = Address::in_default_space(image_base);

        let relocation_address = image_base
            .checked_add(0x21f30u64)
            .expect("valid relocation");
        let expected_value = image_base
            .checked_add(0x6e10u64)
            .expect("valid relocation value");

        let mut relocated_value = None;
        let segments = load_image_bytes(&elf)?;

        for segm in &segments {
            if !segm.contains_address(relocation_address) {
                continue;
            }

            let offset = segm
                .offset_of(relocation_address)
                .expect("address contained in segment");
            relocated_value = segm.read_value::<u64>(offset);
            break;
        }

        assert_eq!(relocated_value, Some(expected_value.offset()));

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_arm_rebased_dynamic_relocations() -> Result<(), Box<dyn std::error::Error>> {
        let mut attributes = AttributeMap::new();
        let image_base = RawAddress::new(0x5000_0000u64);

        attributes.set_attr(ATTRIBUTE_IMAGE_BASE, image_base);

        let elf = Elf::new_with(BytesOrMapping::from_file("tests/libipmi.so")?, attributes)?;
        let (relocation_offset, relocation_value) = with_elf!(
            elf.loaded_view(),
            file | (|| {
                let mut relocs = file.dynamic_relocations()?;
                relocs.find_map(|(offset, reloc)| {
                    let RelocationFlags::Elf { r_type } = reloc.flags() else {
                        return None;
                    };

                    (r_type == R_ARM_RELATIVE).then_some((offset, reloc.addend()))
                })
            })()
        )
        .expect("R_ARM_RELATIVE relocation");

        let image_base = Address::in_default_space(image_base);

        let relocation_address = image_base
            .checked_add(relocation_offset)
            .expect("ARM relocation address");
        let expected_value = image_base.offset().wrapping_add_signed(relocation_value);

        let mut relocated_value = None;
        let segments = load_image_bytes(&elf)?;

        for segm in &segments {
            if !segm.contains_address(relocation_address) {
                continue;
            }

            let offset = segm
                .offset_of(relocation_address)
                .expect("ARM relocation offset");
            relocated_value = segm.read_value::<u32>(offset);
            break;
        }

        assert_eq!(relocated_value, Some(expected_value as u32));

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_arm_relocation_mapping_hints() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new(BytesOrMapping::from_file("tests/libipmi.so")?)?;
        let arch = elf.architecture();
        let thumb_context = arch
            .canonicalise_address(RawAddress::from(1u64))
            .expect("odd thumb pointer canonicalises")
            .1;

        let mut contents = elf.image_contents();
        let mut code_hints = 0usize;
        let mut data_hints = 0usize;
        while let Some(segment) = contents.next()? {
            for hint in segment.function_hints() {
                assert_eq!(
                    hint.offset() & 1,
                    0,
                    "relocation-discovered function hint {hint} must land on an even entry",
                );
            }
            for (address, hint) in segment.mapping_hints() {
                if hint.is_data() {
                    data_hints += 1;
                    assert_eq!(
                        hint.context(),
                        None,
                        "data mapping hint {address} must not carry a processor context",
                    );
                } else {
                    code_hints += 1;
                    assert_eq!(
                        address.offset() & 1,
                        0,
                        "thumb mapping hint {address} must land on an even entry",
                    );
                    assert_eq!(
                        hint.context(),
                        Some(&thumb_context),
                        "thumb mapping hint must carry TMode=1",
                    );
                }
            }
        }

        assert_eq!(
            code_hints, 0,
            "libipmi.so has no relocation that targets a thumb function: its 16 odd-valued \
             dynamic symbols are all STT_OBJECT, reached by 13 R_ARM_GLOB_DAT relocations, so \
             they are data hints; a non-zero count means dynamic symbols are misindexed again",
        );
        assert!(
            data_hints > 0,
            "libipmi.so references data objects via GLOB_DAT relocations",
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_dynamic_symbol_indices_match_the_file() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new(BytesOrMapping::from_file("tests/ls.elf")?)?;

        let mismatched = with_elf!(
            elf.loaded_view(),
            file | file
                .dynamic_symbols()
                .filter_map(|symbol| {
                    let name = symbol.name().ok().filter(|name| !name.is_empty())?;
                    let index = SymbolIndex::new(ELF_DYNSYM_SELECTOR, symbol.index().0);
                    let (_, entry) = elf.image_symbols().get_by_index(index)?;

                    (entry.symbol() != name)
                        .then(|| format!("{index:?} is {name} in the file, {}", entry.symbol()))
                })
                .collect::<Vec<_>>()
        );

        assert!(
            mismatched.is_empty(),
            "{} dynamic symbols are stored under the wrong index, e.g. {:?}",
            mismatched.len(),
            mismatched.first()
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_arm_jump_slot_relocations() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new(BytesOrMapping::from_file("tests/libipmi.so")?)?;
        let (relocation_offset, expected_value) = with_elf!(
            elf.loaded_view(),
            file | (|| {
                let mut relocs = file.dynamic_relocations()?;
                relocs.find_map(|(offset, reloc)| {
                    let RelocationFlags::Elf { r_type } = reloc.flags() else {
                        return None;
                    };

                    if r_type != R_ARM_JUMP_SLOT {
                        return None;
                    }

                    let RelocationTarget::Symbol(index) = reloc.target() else {
                        return None;
                    };

                    elf.image_symbols()
                        .get_by_index(SymbolIndex::new(ELF_DYNSYM_SELECTOR, index.0))
                        .map(|(_, entry)| (offset, entry.address().offset().offset()))
                })
            })()
        )
        .expect("R_ARM_JUMP_SLOT relocation");

        let relocation_address = elf
            .base_address()
            .checked_add(relocation_offset)
            .expect("ARM jump slot address");

        let mut relocated_value = None;
        let segments = load_image_bytes(&elf)?;

        for segm in &segments {
            if !segm.contains_address(relocation_address) {
                continue;
            }

            let offset = segm
                .offset_of(relocation_address)
                .expect("ARM jump slot offset");
            relocated_value = segm.read_value::<u32>(offset);
            break;
        }

        assert_eq!(relocated_value, Some(expected_value as u32));

        Ok(())
    }

    #[test]
    fn test_elf_exec_reject_rebase() -> Result<(), Box<dyn std::error::Error>> {
        let mut attributes = AttributeMap::new();
        attributes.set_attr(ATTRIBUTE_IMAGE_BASE, RawAddress::new(0x1000_0000u64));

        let result = Elf::new_with(BytesOrMapping::from_file("tests/executable")?, attributes);

        assert!(result.is_err());

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_overlapping_segments() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new(BytesOrMapping::from_file("tests/overlapping-segments.so")?)?;

        let layout = elf.image_layout();
        let base_space = ImageSpaceHandle::default();

        let handles = layout
            .spaces()
            .iter()
            .map(|space| space.handle())
            .collect::<BTreeSet<_>>();
        assert!(handles.contains(&base_space));
        assert_eq!(
            handles.len(),
            layout.spaces().len(),
            "duplicate space handle"
        );

        let mut base_spaces = 0usize;
        let mut overlay_spaces = 0usize;
        for space in layout.spaces() {
            match space.kind() {
                ImageSpaceKind::Base { .. } => base_spaces += 1,
                ImageSpaceKind::Overlay { base } => {
                    assert_eq!(
                        base, base_space,
                        "overlay must be anchored to the base space"
                    );
                    overlay_spaces += 1;
                }
            }
        }
        assert_eq!(base_spaces, 1, "expected exactly one base space");
        assert!(overlay_spaces > 0, "sample is expected to overlap");

        let mut overlay_segments = 0usize;
        let mut segments = elf.image_segments();
        while let Some(segment) = segments.next()? {
            assert!(
                handles.contains(&segment.address().space()),
                "segment references an undeclared space"
            );
            let backing = segment.backing().expect("segment is backed");
            assert_eq!(
                backing.bank(),
                ImageBankHandle::default(),
                "overlapping segments alias the shared default bank"
            );
            if segment.address().space() != base_space {
                overlay_segments += 1;
            }
        }
        assert!(overlay_segments > 0, "expected overlay-spaced segments");

        let mut symbols = 0usize;
        for (_, entry) in elf.image_symbols().iter() {
            assert!(
                handles.contains(&entry.address().space()),
                "symbol resolved into an undeclared space"
            );
            symbols += 1;
        }
        assert!(symbols > 0);

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_overlapping_segments_distinct_storage_spaces()
    -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new(BytesOrMapping::from_file("tests/overlapping-segments.so")?)?;

        let mut attributes = AttributeMap::new();
        let (_storage, resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(&elf, &mut attributes)?
                .into_parts();

        let space_ids = elf
            .image_layout()
            .spaces()
            .iter()
            .map(|space| {
                resolution
                    .resolve_space(space.handle())
                    .expect("space resolved")
            })
            .collect::<BTreeSet<_>>();

        assert!(
            space_ids.len() > 1,
            "overlapping ELF must map its image spaces to multiple storage spaces, got {}",
            space_ids.len(),
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_overlapping_sections_distinct_content() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new(BytesOrMapping::from_file("tests/overlapping-sections.elf")?)?;
        let mut attributes = AttributeMap::new();
        let (storage, _resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(&elf, &mut attributes)?
                .into_parts();

        let overlap = RawAddress::from(0x1020u64);
        let mut base_byte = None;
        let mut overlay_bytes = BTreeSet::new();
        for space in storage.spaces() {
            let mut buf = [0u8; 1];
            if storage
                .read_bytes_in_space(space.id(), overlap, &mut buf)
                .unwrap_or(0)
                != 1
            {
                continue;
            }
            if space.is_overlay() {
                overlay_bytes.insert(buf[0]);
            } else {
                base_byte = Some(buf[0]);
            }
        }
        assert_eq!(
            base_byte,
            Some(0xBBu8),
            "base space must expose the later section (.data) at the overlap"
        );
        assert!(
            overlay_bytes.contains(&0xAAu8),
            "an overlay space must expose the earlier section (.text) at the overlap, saw {overlay_bytes:?}"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_image_writes_no_double_emit() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new(BytesOrMapping::from_file("tests/ls.elf")?)?;

        let mut covered = RawAddressRangeSet::new();
        let mut count = 0usize;

        for CapturedImageWrite {
            offset: start,
            bytes,
        } in image_writes(&elf)?
        {
            let len = bytes.len();
            if len == 0 {
                continue;
            }

            let range = start..=start + (len as u64 - 1);

            assert!(
                !covered.intersects_range(range.clone()),
                "image_contents emitted an overlapping bank range at {start:?}"
            );

            covered.insert_range(range);
            count += 1;
        }

        assert!(count > 0);

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_metadata_lazy() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::from_file_with("tests/ls.elf", AttributeMap::new())?;
        let meta = elf.metadata();

        assert_eq!(meta.path(), Some("tests/ls.elf"));

        let bytes = std::fs::read("tests/ls.elf")?;
        let eager = LoadableMetadata::new(&bytes, "probe");
        assert_eq!(meta.md5(), eager.md5());
        assert_eq!(meta.sha256(), eager.sha256());

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_elf_sparse_uninitialised() -> Result<(), Box<dyn std::error::Error>> {
        let elf = Elf::new(BytesOrMapping::from_file("tests/overlapping-segments.so")?)?;

        let materialised = image_writes(&elf)?
            .iter()
            .map(|write| write.bytes.len())
            .sum::<usize>();

        assert!(
            materialised < 64 * 1024 * 1024,
            "image_contents must not materialise the uninitialised .bss (got {materialised} bytes)"
        );

        Ok(())
    }
}
