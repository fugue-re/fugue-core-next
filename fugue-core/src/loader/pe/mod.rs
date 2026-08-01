use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::OnceLock;

use bitflags::bitflags;
use fallible_iterator::FallibleIterator;
use object::endian::LittleEndian as LE;
use object::pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SIZEOF_FILE_HEADER, IMAGE_SIZEOF_SECTION_HEADER,
    ImageNtHeaders32, ImageNtHeaders64,
};
use object::read::pe::{
    self, ImageNtHeaders, ImageOptionalHeader, PeFile, PeSection, PeSectionIterator,
};
use object::{FileKind, Object, ObjectSection, ReadRef, SectionFlags};
use smallvec::{SmallVec, smallvec};

use crate::arch::Arch;
use crate::ir::{
    Endian, ExternSegment, RawAddress, RawAddressRangeSet, SegmentProperties, Symbol, SymbolIndex,
    SymbolProperties, SymbolTableSelector, TransientSymbolTable,
};
use crate::lifter::ContextHint;
use crate::loader::pe::extensions::ImageContext;
use crate::loader::{
    ImageAddress, ImageBacking, ImageBank, ImageBankHandle, ImageBankLayout, ImageCoveredRegions,
    ImageLayout, ImageRegionBankMap, ImageSegment, ImageSegmentContents,
    ImageSegmentContentsIterator, ImageSegmentIterator, ImageSpace, ImageSpaceHandle, ImageSpaces,
    Loadable, LoadableAnalysers, LoadableFromBytes, LoadableFromFile, LoadableMetadata,
    LoaderError,
};
use crate::platform::{Format, OperatingSystem, Platform};
use crate::storage::segments::mapping::SegmentMappingProvenance;
use crate::types::attributes::{ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_IMAGE_BASE};
use crate::types::{AttributeMap, BytesOrMapping};

mod analysers;
pub use analysers::PeAnalysers;

pub mod extensions;

mod permissive;

mod relocations;
pub use relocations::PeSegmentRelocator;

pub const PE_EXPORT_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(0);
pub const PE_IMPORT_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(1);

pub const ATTRIBUTE_PERMISSIVE: &str = "loader.pe.permissive";
pub const ATTRIBUTE_LOAD_HEADERS: &str = "loader.pe.load_headers";

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub(crate) struct PeLoaderProperties: u8 {
        const PERMISSIVE = 0b0000_0001;
        const LOAD_HEADERS = 0b0000_0010;
    }
}

impl PeLoaderProperties {
    pub(crate) fn new(attributes: &AttributeMap) -> Self {
        let mut config = Self::empty();

        if attributes
            .get_attr::<bool>(ATTRIBUTE_PERMISSIVE)
            .unwrap_or_default()
        {
            config.insert(Self::PERMISSIVE);
        }

        if attributes
            .get_attr::<bool>(ATTRIBUTE_LOAD_HEADERS)
            .unwrap_or_default()
        {
            config.insert(Self::LOAD_HEADERS);
        }

        config
    }

    pub(crate) fn is_permissive(&self) -> bool {
        self.contains(Self::PERMISSIVE)
    }

    pub(crate) fn load_headers(&self) -> bool {
        self.contains(Self::LOAD_HEADERS)
    }
}

#[ouroboros::self_referencing]
struct PeInner<'a> {
    data: BytesOrMapping<'a>,
    #[borrows(data)]
    #[covariant]
    loaded: PeLoadedRepr<'this, 'a>,
}

pub enum PeFileRepr<'this, 'data> {
    Pe32(PeFile<'this, ImageNtHeaders32, &'this BytesOrMapping<'data>>),
    Pe64(PeFile<'this, ImageNtHeaders64, &'this BytesOrMapping<'data>>),
}

macro_rules! with_pe {
    ($inner:expr, $var:ident | $body:expr) => {
        match $inner {
            PeFileRepr::Pe32($var) => $body,
            PeFileRepr::Pe64($var) => $body,
        }
    };
}

impl<'this, 'data> PeFileRepr<'this, 'data> {
    pub(crate) fn is_64(&self) -> bool {
        with_pe!(self, pe | pe.is_64())
    }

    pub fn operating_system(&self) -> OperatingSystem {
        const EFI_SUBSYSTEMS: std::ops::RangeInclusive<u16> = 10..=13;

        let subsystem = with_pe!(self, pe | pe.nt_headers().optional_header().subsystem());

        if EFI_SUBSYSTEMS.contains(&subsystem) {
            OperatingSystem::Uefi
        } else {
            OperatingSystem::Windows
        }
    }

    pub(crate) fn machine(&self) -> u16 {
        with_pe!(self, pe | pe.nt_headers().file_header().machine.get(LE))
    }

    fn parse(data: &'this BytesOrMapping<'data>) -> Result<Self, LoaderError> {
        let pe = match FileKind::parse(data).map_err(LoaderError::format)? {
            FileKind::Pe32 => Self::Pe32(pe::PeFile32::parse(data).map_err(LoaderError::format)?),
            FileKind::Pe64 => Self::Pe64(pe::PeFile64::parse(data).map_err(LoaderError::format)?),
            _ => return Err(LoaderError::format_with("input is not a PE image")),
        };

        Ok(pe)
    }
}

impl<'a> PeInner<'a> {
    fn from_bytes(
        data: BytesOrMapping<'a>,
        attributes: &AttributeMap,
    ) -> Result<Self, LoaderError> {
        Self::try_new(data, |data| PeLoadedRepr::parse(data, attributes))
    }

    fn from_bytes_or_recover(
        data: BytesOrMapping<'a>,
        attributes: &AttributeMap,
    ) -> Result<Self, PeRecoverError<'a>> {
        Self::try_new_or_recover(data, |data| PeLoadedRepr::parse(data, attributes))
            .map_err(|(error, heads)| Box::new((heads.data, error)))
    }
}

type PeRecoverError<'a> = Box<(BytesOrMapping<'a>, LoaderError)>;

pub struct Pe<'a> {
    object: PeInner<'a>,
    metadata: OnceLock<LoadableMetadata>,
    path: Option<String>,
    attributes: AttributeMap,
}

impl<'a> Pe<'a> {
    pub fn new(data: impl Into<BytesOrMapping<'a>>) -> Result<Self, LoaderError> {
        Self::new_with(data, AttributeMap::new())
    }

    pub fn new_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        let attributes = attributes.into();
        let config = PeLoaderProperties::new(&attributes);

        let (data, error) = match PeInner::from_bytes_or_recover(data.into(), &attributes) {
            Ok(object) => return Ok(Self::from_inner(object, attributes)),
            Err(failed) => *failed,
        };

        if !config.is_permissive() {
            return Err(error);
        }

        let Some(repaired) = permissive::try_repair(data)? else {
            return Err(error);
        };

        let object = PeInner::from_bytes(repaired, &attributes)?;
        Ok(Self::from_inner(object, attributes))
    }

    fn from_inner(object: PeInner<'a>, attributes: AttributeMap) -> Self {
        let mut slf = Self {
            object,
            metadata: OnceLock::new(),
            path: None,
            attributes,
        };

        if let Some(entry) = slf.entry() {
            slf.attributes.set_attr(ATTRIBUTE_ENTRY_POINT, entry);
        }

        slf
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, LoaderError> {
        Self::from_file_with(path, AttributeMap::new())
    }

    pub fn from_file_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        <Self as LoadableFromFile>::from_file_with(path, attributes)
    }

    pub fn entry(&self) -> Option<RawAddress> {
        let loaded = self.object.borrow_loaded();
        let state = &loaded.state;
        let entry = with_pe!(&loaded.view, pe | pe.entry());
        (entry != 0).then(|| RawAddress::from(state.rebase_offset(entry)))
    }

    pub fn loaded_view(&self) -> &PeFileRepr<'_, 'a> {
        &self.object.borrow_loaded().view
    }

    pub fn mapping_hints(&self) -> &BTreeMap<RawAddress, ContextHint> {
        &self.object.borrow_loaded().state.mapping_hints
    }

    pub fn image_symbols(&self) -> &TransientSymbolTable<ImageAddress> {
        &self.object.borrow_loaded().state.symbols
    }

    pub fn extern_segment(&self) -> &ExternSegment {
        &self.object.borrow_loaded().state.extern_segm
    }
}

struct PeLoadedRepr<'this, 'data> {
    view: PeFileRepr<'this, 'data>,
    state: PeLoadState,
}

impl<'this, 'data> PeLoadedRepr<'this, 'data> {
    fn parse(
        data: &'this BytesOrMapping<'data>,
        attributes: &AttributeMap,
    ) -> Result<Self, LoaderError> {
        let view = PeFileRepr::parse(data)?;
        let state = PeLoadState::from_view(&view, attributes)?;

        Ok(Self { view, state })
    }
}

struct PeLoadState {
    architecture: Arch,
    base: RawAddress,
    preferred_base: RawAddress,
    entry: Option<ImageAddress>,
    layout: ImageLayout,
    mapping_hints: BTreeMap<RawAddress, ContextHint>,
    symbols: TransientSymbolTable<ImageAddress>,
    extern_segm: ExternSegment,
    import_slots: BTreeMap<RawAddress, RawAddress>,
    segments: Vec<PeImageSegment>,
    region_bank: PeRegionBankMap,
}

impl PeLoadState {
    fn from_view(
        view: &PeFileRepr<'_, '_>,
        attributes: &AttributeMap,
    ) -> Result<Self, LoaderError> {
        let preferred_base = RawAddress::from(with_pe!(view, pe | pe.relative_address_base()));

        let base = attributes
            .get_attr::<RawAddress>(ATTRIBUTE_IMAGE_BASE)
            .unwrap_or(preferred_base);

        if base != preferred_base {
            let has_relocations = with_pe!(
                view,
                pe | pe.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC).is_some()
            );

            if !has_relocations {
                return Err(LoaderError::format_with(
                    "cannot rebase PE image without a base relocation directory",
                ));
            }
        }

        let entry = with_pe!(view, pe | pe.entry());
        let entry = if entry != 0 {
            Some(
                entry
                    .checked_sub(preferred_base.offset())
                    .and_then(|offset| base.checked_add(offset))
                    .ok_or_else(|| LoaderError::address_overflow(base))?,
            )
        } else {
            None
        };
        let image_entry = entry.map(|entry| ImageAddress::in_default_space(entry.offset()));
        let context = ImageContext::new(view, base, preferred_base, entry, attributes);
        let architecture = context.resolve_architecture()?;
        let config = PeLoaderProperties::new(attributes);

        let symbols = with_pe!(
            view,
            pe | PeSymbolData::from_pe(pe, &architecture, base, preferred_base)
        )?;

        let PeSymbolData {
            bounds,
            mapping_hints,
            symbols,
            extern_segm,
            import_slots,
        } = symbols;
        let bank_base = if config.load_headers() {
            base.min(*bounds.start())
        } else {
            *bounds.start()
        };
        let bank_last = bounds
            .end()
            .checked_offset_from(bank_base)
            .and_then(|size| bank_base.checked_add(size))
            .ok_or_else(|| LoaderError::address_overflow(base))?;

        let (placements, spaces, bank_layout) = with_pe!(
            view,
            pe | {
                let mut walk = PeSegmentWalk::new(
                    pe,
                    base,
                    preferred_base,
                    ImageBank::new_in_default(bank_base..=bank_last),
                    &extern_segm,
                    config,
                )?;
                let mut placements = Vec::new();
                while let Some(placement) = walk.next_segment()? {
                    placements.push(placement);
                }
                let (spaces, bank_layout) = walk.into_parts();
                (placements, spaces, bank_layout)
            }
        );

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

        let (banks, region_bank) = bank_layout.into_parts();

        let layout = ImageLayout::new(banks, spaces);

        Ok(Self {
            architecture,
            base,
            preferred_base,
            entry: image_entry,
            layout,
            mapping_hints,
            symbols: image_symbols,
            extern_segm,
            import_slots,
            segments: placements,
            region_bank,
        })
    }

    fn rebase_offset(&self, address: u64) -> u64 {
        (self.base - self.preferred_base)
            .offset()
            .wrapping_add(address)
    }
}

struct RawPeSymbol {
    address: RawAddress,
    symbol: Symbol,
    properties: SymbolProperties,
}

struct PeSymbolData {
    bounds: RangeInclusive<RawAddress>,
    mapping_hints: BTreeMap<RawAddress, ContextHint>,
    symbols: BTreeMap<SymbolIndex, RawPeSymbol>,
    extern_segm: ExternSegment,
    import_slots: BTreeMap<RawAddress, RawAddress>,
}

impl PeSymbolData {
    fn from_pe<'data, Pe, R>(
        pe: &PeFile<'data, Pe, R>,
        arch: &Arch,
        base: RawAddress,
        preferred_base: RawAddress,
    ) -> Result<Self, LoaderError>
    where
        Pe: ImageNtHeaders,
        R: ReadRef<'data>,
    {
        let addr_size = arch.language().address_size();
        let addr_align = arch.language().address_alignment().max(addr_size);

        let mut sections = Vec::new();
        let mut bounds = None::<(RawAddress, RawAddress)>;

        for sect in pe.sections() {
            if sect.size() == 0 {
                continue;
            }

            let address = sect
                .address()
                .checked_sub(preferred_base.offset())
                .and_then(|offset| base.checked_add(offset))
                .ok_or_else(|| LoaderError::address_overflow(base))?;
            let last_address = address
                .checked_add(sect.size().wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(base))?;
            bounds = Some(match bounds {
                Some((min, max)) => (min.min(address), max.max(last_address)),
                None => (address, last_address),
            });
            sections.push((address, last_address, pe_section_properties(&sect)));
        }

        let (min_addr, max_addr) = bounds.unwrap_or((base, base));
        let extern_base = max_addr
            .checked_add(addr_size)
            .ok_or_else(|| LoaderError::address_overflow(base))?;
        let aligned_extern_base = extern_base.align(addr_align);

        if aligned_extern_base < extern_base {
            return Err(LoaderError::address_overflow(base));
        }

        let mut symbols = BTreeMap::<SymbolIndex, RawPeSymbol>::new();
        let mut extern_segm = ExternSegment::new(
            aligned_extern_base,
            addr_align,
            arch.external_thunk_template(),
        );
        let mut import_slots = BTreeMap::new();
        let mut externs = BTreeMap::<Symbol, RawAddress>::new();

        for (index, export) in pe
            .exports()
            .map_err(LoaderError::format)?
            .into_iter()
            .enumerate()
        {
            let address = export
                .address()
                .checked_sub(preferred_base.offset())
                .and_then(|offset| base.checked_add(offset))
                .ok_or_else(|| LoaderError::address_overflow(base))?;
            let properties = symbol_properties_for_address(address, &sections)
                | SymbolProperties::LOCAL
                | SymbolProperties::EXPORT;
            symbols.insert(
                SymbolIndex::new(PE_EXPORT_SELECTOR, index),
                RawPeSymbol {
                    address,
                    symbol: String::from_utf8_lossy(export.name()).into_owned().into(),
                    properties,
                },
            );
        }

        if let Some(import_table) = pe.import_table().map_err(LoaderError::format)? {
            let mut descriptors = import_table.descriptors().map_err(LoaderError::format)?;
            let mut import_index = 0usize;

            while let Some(descriptor) = descriptors.next().map_err(LoaderError::format)? {
                let library = String::from_utf8_lossy(
                    import_table
                        .name(descriptor.name.get(LE))
                        .map_err(LoaderError::format)?,
                );

                let mut lookup = descriptor.original_first_thunk.get(LE);
                let address_table = descriptor.first_thunk.get(LE);

                if lookup == 0 {
                    lookup = address_table;
                }

                let mut thunks = import_table.thunks(lookup).map_err(LoaderError::format)?;
                let thunk_size = if pe.is_64() { 8u32 } else { 4u32 };
                let mut thunk_index = 0u32;

                while let Some(thunk) = thunks.next::<Pe>().map_err(LoaderError::format)? {
                    let name = match import_table
                        .import::<Pe>(thunk)
                        .map_err(LoaderError::format)?
                    {
                        pe::Import::Ordinal(ordinal) => format!("{library}!#{ordinal}"),
                        pe::Import::Name(_, name) => {
                            let name = String::from_utf8_lossy(name);
                            format!("{library}!{name}")
                        }
                    };

                    let symbol = Symbol::from(&name);
                    let extern_address = match externs.entry(symbol) {
                        Entry::Occupied(entry) => *entry.get(),
                        Entry::Vacant(entry) => {
                            let addr = extern_segm
                                .add_extern()
                                .ok_or_else(|| LoaderError::address_overflow(base))?;
                            *entry.insert(addr)
                        }
                    };

                    symbols.insert(
                        SymbolIndex::new(PE_IMPORT_SELECTOR, import_index),
                        RawPeSymbol {
                            address: extern_address,
                            symbol,
                            properties: SymbolProperties::EXTERN | SymbolProperties::FUNCTION,
                        },
                    );

                    let thunk_offset = (thunk_index as u64)
                        .checked_mul(thunk_size as u64)
                        .ok_or_else(|| LoaderError::address_overflow(base))?;
                    let slot_offset = (address_table as u64)
                        .checked_add(thunk_offset)
                        .ok_or_else(|| LoaderError::address_overflow(base))?;
                    let slot = base
                        .checked_add(slot_offset)
                        .ok_or_else(|| LoaderError::address_overflow(base))?;

                    import_slots.insert(slot, extern_address);

                    import_index += 1;
                    thunk_index = thunk_index
                        .checked_add(1)
                        .ok_or_else(|| LoaderError::address_overflow(base))?;
                }
            }
        }

        let max_addr = extern_segm.last_address().unwrap_or(max_addr);

        Ok(Self {
            bounds: min_addr..=max_addr,
            mapping_hints: BTreeMap::new(),
            symbols,
            extern_segm,
            import_slots,
        })
    }
}

fn symbol_properties_for_address(
    address: RawAddress,
    sections: &[(RawAddress, RawAddress, SegmentProperties)],
) -> SymbolProperties {
    sections
        .iter()
        .find(|(start, end, _)| address >= *start && address <= *end)
        .map_or(SymbolProperties::DATA, |(_, _, properties)| {
            if properties.is_executable() {
                SymbolProperties::FUNCTION
            } else {
                SymbolProperties::DATA
            }
        })
}

fn pe_section_properties<'data, Pe, R>(sect: &PeSection<'data, '_, Pe, R>) -> SegmentProperties
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    let SectionFlags::Coff { characteristics } = sect.flags() else {
        return SegmentProperties::empty();
    };

    let mut props = SegmentProperties::empty();

    if characteristics & IMAGE_SCN_MEM_READ != 0 {
        props.insert(SegmentProperties::PERM_READ);
    }

    if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
        props.insert(SegmentProperties::PERM_WRITE);
    }

    if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
        props.insert(SegmentProperties::PERM_EXECUTE);
    }

    if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
        || matches!(sect.file_range(), None | Some((_, 0)))
    {
        props.insert(SegmentProperties::UNINITIALISED);
    }

    props
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PeRegionSourceKind {
    Header,
    Section,
    Extern,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PeRegionSource {
    kind: PeRegionSourceKind,
    index: usize,
}

impl PeRegionSource {
    fn new(kind: PeRegionSourceKind, index: usize) -> Self {
        Self { kind, index }
    }

    fn header() -> Self {
        Self::new(PeRegionSourceKind::Header, 0)
    }

    fn section(index: usize) -> Self {
        Self::new(PeRegionSourceKind::Section, index)
    }

    fn externs() -> Self {
        Self::new(PeRegionSourceKind::Extern, 0)
    }
}

type PeCoveredRegions = ImageCoveredRegions;
type PeRegionBankMap = ImageRegionBankMap<PeRegionSource>;
type PeBankLayout = ImageBankLayout<PeRegionSource>;

struct PeHeaderRegion<'data> {
    data: &'data [u8],
}

impl<'data> PeHeaderRegion<'data> {
    fn new<Pe, R>(pe: &PeFile<'data, Pe, R>) -> Result<Option<Self>, LoaderError>
    where
        Pe: ImageNtHeaders,
        R: ReadRef<'data>,
    {
        const PE_SIGNATURE_SIZE: u64 = 4;

        let file_len = pe
            .data()
            .len()
            .map_err(|_| LoaderError::format_with("invalid PE data"))?;
        let dos_size = u64::from(pe.dos_header().nt_headers_offset());
        let file_header_size = IMAGE_SIZEOF_FILE_HEADER as u64;
        let section_header_size = IMAGE_SIZEOF_SECTION_HEADER as u64;
        let optional_header_size = u64::from(
            pe.nt_headers()
                .file_header()
                .size_of_optional_header
                .get(LE),
        );
        let section_count = u64::from(pe.nt_headers().file_header().number_of_sections.get(LE));
        let sections = section_header_size
            .checked_mul(section_count)
            .ok_or_else(|| LoaderError::format_with("PE header size overflow"))?;
        let computed_size = [
            PE_SIGNATURE_SIZE,
            file_header_size,
            optional_header_size,
            sections,
        ]
        .into_iter()
        .try_fold(dos_size, u64::checked_add)
        .ok_or_else(|| LoaderError::format_with("PE header size overflow"))?;
        let header_size = computed_size
            .max(u64::from(
                pe.nt_headers().optional_header().size_of_headers(),
            ))
            .min(file_len);
        if header_size == 0 {
            return Ok(None);
        }
        let data = pe
            .data()
            .read_bytes_at(0, header_size)
            .map_err(|_| LoaderError::format_with("invalid PE header range"))?;
        Ok(Some(Self { data }))
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn data(&self) -> &'data [u8] {
        self.data
    }
}

struct PeImageSegmentContents<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pe: &'file PeFile<'data, Pe, R>,
    sects: PeSectionIterator<'data, 'file, Pe, R>,
    covered: PeCoveredRegions,
    current_base: RawAddress,
    preferred_base: RawAddress,
    import_slots: &'file BTreeMap<RawAddress, RawAddress>,
    extern_segm: Option<&'file ExternSegment>,
    endian: Endian,
    region_bank: &'file PeRegionBankMap,
    header: Option<Result<Option<PeHeaderRegion<'data>>, LoaderError>>,
    config: PeLoaderProperties,
}

impl<'data, 'file, Pe, R> PeImageSegmentContents<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        pe: &'file PeFile<'data, Pe, R>,
        endian: Endian,
        current_base: RawAddress,
        preferred_base: RawAddress,
        import_slots: &'file BTreeMap<RawAddress, RawAddress>,
        extern_segm: &'file ExternSegment,
        region_bank: &'file PeRegionBankMap,
        config: PeLoaderProperties,
    ) -> Self {
        let header = config.load_headers().then(|| PeHeaderRegion::new(pe));
        Self {
            pe,
            sects: pe.sections(),
            covered: PeCoveredRegions::new(),
            current_base,
            preferred_base,
            import_slots,
            extern_segm: Some(extern_segm),
            endian,
            region_bank,
            header,
            config,
        }
    }

    fn relocator(&self) -> PeSegmentRelocator<'data, 'file, Pe, R> {
        PeSegmentRelocator::new(
            self.pe,
            self.current_base,
            self.preferred_base,
            self.import_slots,
        )
    }

    fn header_segment(&mut self) -> Result<Option<ImageSegmentContents<'data>>, LoaderError> {
        let Some(header) = self.header.take() else {
            return Ok(None);
        };
        let Some(header) = header? else {
            return Ok(None);
        };
        let size = header.size();
        let last_address = self
            .current_base
            .checked_add(size.wrapping_sub(1))
            .ok_or_else(|| LoaderError::address_overflow(self.current_base))?;
        let bank = self
            .region_bank
            .bank_for(PeRegionSource::header())
            .unwrap_or_default();

        self.covered
            .insert_range(bank, self.current_base..=last_address);

        Ok(Some(ImageSegmentContents::new_sparse_in_bank(
            bank,
            self.current_base,
            self.endian,
            header.data(),
            size,
        )))
    }

    fn extern_segment(&mut self) -> Result<Option<ImageSegmentContents<'data>>, LoaderError> {
        let Some(externs) = self
            .extern_segm
            .take()
            .filter(|externs| !externs.is_empty())
        else {
            return Ok(None);
        };

        let extern_padding = externs.aligned_template_size() - externs.template().len();
        let address = externs.address();
        let last_address = externs.last_address().expect("not empty");

        let mut bytes = Vec::with_capacity(externs.size());
        for _ in externs.iter() {
            bytes.extend_from_slice(externs.template().bytes());
            bytes.resize(bytes.len() + extern_padding, 0);
        }

        let range = address..=last_address;
        let bank = self
            .region_bank
            .bank_for(PeRegionSource::externs())
            .unwrap_or_default();
        self.covered.insert_range(bank, range);

        Ok(Some(ImageSegmentContents::new_in_bank(
            bank,
            address,
            self.endian,
            Cow::Owned(bytes),
        )))
    }

    fn next_section(&mut self) -> Result<Option<ImageSegmentContents<'data>>, LoaderError> {
        let relocator = self.relocator();

        for sect in self.sects.by_ref() {
            if sect.size() == 0 {
                continue;
            }

            let address = (self.current_base - self.preferred_base) + sect.address();
            let last_address = address
                .checked_add(sect.size().wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(self.current_base))?;

            let vrange = address..=last_address;
            let bank = self
                .region_bank
                .bank_for(PeRegionSource::section(sect.index().0))
                .unwrap_or_default();

            if self.covered.intersects_range(bank, vrange.clone()) {
                tracing::debug!("overlapping PE section {address}-{last_address}; skipping");
                continue;
            }

            let data = sect.data().unwrap_or_default();
            let emit = (data.len() as u64).min(sect.size()) as usize;

            let mut bytes = ImageSegmentContents::new_sparse_in_bank(
                bank,
                address,
                self.endian,
                &data[..emit],
                sect.size(),
            );

            self.covered.insert_range(bank, vrange);
            relocator.apply(&mut bytes)?;

            return Ok(Some(bytes));
        }

        self.extern_segment()
    }
}

impl<'data, 'file, Pe, R> FallibleIterator for PeImageSegmentContents<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    type Error = LoaderError;
    type Item = ImageSegmentContents<'data>;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.config.load_headers()
            && let Some(header) = self.header_segment()?
        {
            return Ok(Some(header));
        }
        self.next_section()
    }
}

struct PeRegion<'data> {
    name: Cow<'data, str>,
    address: RawAddress,
    size: u64,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
    source: PeRegionSource,
}

impl PeRegion<'_> {
    fn source(&self) -> PeRegionSource {
        self.source
    }
}

struct PeImageSegment {
    name: String,
    address: ImageAddress,
    backing_offset: RawAddress,
    size: u64,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
    bank: ImageBankHandle,
}

impl PeImageSegment {
    fn new(region: &PeRegion, space: ImageSpaceHandle, backing_offset: RawAddress) -> Self {
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

struct PeSegmentWalk<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    base: RawAddress,
    preferred_base: RawAddress,
    bank_base: RawAddress,
    base_space: ImageSpaceHandle,
    sects: PeSectionIterator<'data, 'file, Pe, R>,
    extern_segm: Option<&'file ExternSegment>,
    header: Option<PeHeaderRegion<'data>>,
    covered: RawAddressRangeSet,
    spaces: ImageSpaces,
    bank_layout: PeBankLayout,
    config: PeLoaderProperties,
}

impl<'data, 'file, Pe, R> PeSegmentWalk<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn new(
        pe: &'file PeFile<'data, Pe, R>,
        base: RawAddress,
        preferred_base: RawAddress,
        default_bank: ImageBank,
        extern_segm: &'file ExternSegment,
        config: PeLoaderProperties,
    ) -> Result<Self, LoaderError> {
        let base_space = ImageSpaceHandle::default();
        let bank_base = *default_bank.range().start();
        let header = if config.load_headers() {
            PeHeaderRegion::new(pe)?
        } else {
            None
        };
        Ok(Self {
            base,
            preferred_base,
            bank_base,
            base_space,
            sects: pe.sections(),
            extern_segm: Some(extern_segm),
            header,
            covered: RawAddressRangeSet::new(),
            spaces: smallvec![ImageSpace::base(base_space)],
            bank_layout: PeBankLayout::new(default_bank),
            config,
        })
    }

    fn into_parts(self) -> (ImageSpaces, PeBankLayout) {
        (self.spaces, self.bank_layout)
    }

    fn next_region(&mut self) -> Result<Option<PeRegion<'data>>, LoaderError> {
        if self.config.load_headers()
            && let Some(header) = self.header.take()
        {
            return Ok(Some(PeRegion {
                name: Cow::Borrowed("Headers"),
                address: self.base,
                size: header.size(),
                properties: SegmentProperties::PERM_READ,
                provenance: SegmentMappingProvenance::Section,
                source: PeRegionSource::header(),
            }));
        }

        for sect in self.sects.by_ref() {
            if sect.size() == 0 {
                continue;
            }

            let address = (self.base - self.preferred_base) + sect.address();
            let size = sect.size();
            let name = sect
                .name()
                .ok()
                .map_or_else(|| Cow::Borrowed("LOAD"), Cow::Borrowed);

            return Ok(Some(PeRegion {
                name,
                address,
                size,
                properties: pe_section_properties(&sect),
                provenance: SegmentMappingProvenance::Section,
                source: PeRegionSource::section(sect.index().0),
            }));
        }

        Ok(self.extern_region())
    }

    fn extern_region(&mut self) -> Option<PeRegion<'data>> {
        let externs = self
            .extern_segm
            .take()
            .filter(|externs| !externs.is_empty())?;
        Some(PeRegion {
            name: Cow::Borrowed("EXTERN"),
            address: externs.address(),
            size: externs.size() as u64,
            properties: SegmentProperties::EXTERNAL
                | SegmentProperties::PERM_READ
                | SegmentProperties::PERM_EXECUTE,
            provenance: SegmentMappingProvenance::Extern,
            source: PeRegionSource::externs(),
        })
    }

    fn next_segment(&mut self) -> Result<Option<PeImageSegment>, LoaderError> {
        let Some(region) = self.next_region()? else {
            return Ok(None);
        };

        let last = region
            .address
            .checked_add(region.size.saturating_sub(1))
            .ok_or_else(|| LoaderError::address_overflow(region.address))?;
        let backing_offset = region
            .address
            .checked_sub(self.bank_base)
            .ok_or_else(|| LoaderError::address_overflow(region.address))?;
        let range = region.address..=last;
        let overlaps = self.covered.intersects_range(range.clone());

        let (space, bank, backing_offset) = if overlaps {
            let handle = ImageSpaceHandle::new(
                u16::try_from(self.spaces.len()).expect("space count must fit in u16"),
            );
            self.spaces
                .push(ImageSpace::overlay(handle, self.base_space));
            let bank = self.bank_layout.allocate_overlay(range.clone());
            self.bank_layout.route_region(region.source(), bank);
            (handle, bank, RawAddress::from(0u64))
        } else {
            (self.base_space, ImageBankHandle::default(), backing_offset)
        };

        self.covered.insert_range(range);

        let mut segment = PeImageSegment::new(&region, space, backing_offset);
        segment.bank = bank;
        Ok(Some(segment))
    }
}

struct PeImageSegments<'a> {
    segments: std::slice::Iter<'a, PeImageSegment>,
    image_symbols: &'a TransientSymbolTable<ImageAddress>,
    mapping_hints: &'a BTreeMap<RawAddress, ContextHint>,
}

impl<'a> PeImageSegments<'a> {
    fn new(
        segments: &'a [PeImageSegment],
        image_symbols: &'a TransientSymbolTable<ImageAddress>,
        mapping_hints: &'a BTreeMap<RawAddress, ContextHint>,
    ) -> Self {
        Self {
            segments: segments.iter(),
            image_symbols,
            mapping_hints,
        }
    }

    fn image_segment(&self, segment: &'a PeImageSegment) -> ImageSegment<'a> {
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

impl<'a> FallibleIterator for PeImageSegments<'a> {
    type Error = LoaderError;
    type Item = ImageSegment<'a>;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        let Some(segment) = self.segments.next() else {
            return Ok(None);
        };
        Ok(Some(self.image_segment(segment)))
    }
}

impl<'a> LoadableFromBytes<'a> for Pe<'a> {
    fn from_bytes_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        Self::new_with(data, attributes)
    }
}

impl LoadableFromFile for Pe<'_> {
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

impl Loadable for Pe<'_> {
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
                format!("Fugue v{} PE Loader", env!("CARGO_PKG_VERSION")),
            )
        })
    }

    fn architecture(&self) -> Arch {
        self.object.borrow_loaded().state.architecture.clone()
    }

    fn platform(&self) -> Platform {
        self.architecture()
            .platform()
            .with_compiler_spec_id("windows")
            .with_format(Format::Pe)
            .with_os(self.object.borrow_loaded().view.operating_system())
    }

    fn image_symbols(&self) -> Option<&TransientSymbolTable<ImageAddress>> {
        Some(&self.object.borrow_loaded().state.symbols)
    }

    fn entry_point(&self) -> Option<ImageAddress> {
        self.object.borrow_loaded().state.entry
    }

    fn image_segments<'b>(
        &'b self,
    ) -> impl FallibleIterator<Item = ImageSegment<'b>, Error = LoaderError> + 'b {
        let state = &self.object.borrow_loaded().state;

        Box::new(PeImageSegments::new(
            &state.segments,
            &state.symbols,
            &state.mapping_hints,
        )) as ImageSegmentIterator<'b>
    }

    fn image_layout(&self) -> &ImageLayout {
        &self.object.borrow_loaded().state.layout
    }

    fn image_contents<'b>(
        &'b self,
    ) -> impl FallibleIterator<Item = ImageSegmentContents<'b>, Error = LoaderError> + 'b {
        let loaded = self.object.borrow_loaded();
        let view = &loaded.view;
        let state = &loaded.state;

        with_pe!(
            view,
            pe | Box::new(PeImageSegmentContents::new(
                pe,
                self.architecture().endian(),
                state.base,
                state.preferred_base,
                &state.import_slots,
                &state.extern_segm,
                &state.region_bank,
                PeLoaderProperties::new(self.attributes()),
            )) as ImageSegmentContentsIterator<'b>
        )
    }

    fn analysers(&self) -> impl LoadableAnalysers {
        PeAnalysers::new(self)
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    use std::convert::TryInto;
    use std::ops::Range;
    use std::sync::atomic::{AtomicBool, Ordering};

    use fallible_iterator::FallibleIterator;
    use object::endian::LittleEndian as LE;
    use object::pe::{IMAGE_REL_BASED_DIR64, ImageNtHeaders64};
    use object::read::pe::{Import, PeFile64};
    use object::{Object, ObjectSection, ReadRef};

    use super::{
        ATTRIBUTE_LOAD_HEADERS, ATTRIBUTE_PERMISSIVE, Pe, PeImageSegmentContents,
        PeLoaderProperties, PeRegionBankMap, PeSegmentWalk,
    };
    use crate::attributes;
    use crate::ir::{Address, Endian, ExternFunctionTemplate, ExternSegment, RawAddress};
    use crate::loader::{
        ImageAddress, ImageBacking, ImageBank, ImageBankHandle, ImageSegmentContents, Loadable,
        LoaderError,
    };
    use crate::types::BytesOrMapping;
    use crate::types::attributes::ATTRIBUTE_IMAGE_BASE;

    #[derive(Clone, Copy)]
    struct HeaderReadFailure<'a> {
        data: &'a [u8],
        fail: &'a AtomicBool,
    }

    impl<'a> ReadRef<'a> for HeaderReadFailure<'a> {
        fn len(self) -> Result<u64, ()> {
            u64::try_from(<[u8]>::len(self.data)).map_err(|_| ())
        }

        fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
            if self.fail.load(Ordering::SeqCst) && offset == 0 {
                return Err(());
            }
            self.data.read_bytes_at(offset, size)
        }

        fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
            self.data.read_bytes_at_until(range, delimiter)
        }
    }

    struct LoadedSegment {
        address: ImageAddress,
        backing: ImageBacking,
        size: u64,
    }

    struct Placement {
        address: Address,
    }

    impl LoadedSegment {
        fn resolve(&self, bank: ImageBankHandle, offset: u64) -> Option<Placement> {
            if self.backing.bank() != bank {
                return None;
            }

            let start = self.backing.offset().offset();
            let end = start.checked_add(self.size)?;
            if offset < start || offset >= end {
                return None;
            }

            let delta = offset - start;
            let address = Address::from(self.address.offset().offset().wrapping_add(delta));
            Some(Placement { address })
        }
    }

    fn load_segments(
        pe: &Pe<'_>,
    ) -> Result<Vec<ImageSegmentContents<'static>>, Box<dyn std::error::Error>> {
        let mut segments = Vec::new();
        let mut image_segments = pe.image_segments();
        while let Some(segment) = image_segments.next()? {
            if let Some(backing) = segment.backing() {
                segments.push(LoadedSegment {
                    address: segment.address(),
                    backing,
                    size: segment.size(),
                });
            }
        }

        let bank = ImageBankHandle::default();
        let bank_base = pe
            .image_layout()
            .banks()
            .iter()
            .find(|entry| entry.handle() == bank)
            .map(|entry| *entry.range().start())
            .expect("default bank");

        let mut contents = pe.image_contents();
        let mut loaded = Vec::new();

        while let Some(segment) = contents.next()? {
            for write in segment.into_writes(bank_base)? {
                let placement = segments
                    .iter()
                    .find_map(|segment| segment.resolve(write.bank(), write.offset().offset()))
                    .unwrap_or_else(|| Placement {
                        address: Address::from(write.offset().offset()),
                    });

                loaded.push(ImageSegmentContents::new(
                    placement.address,
                    pe.architecture().endian(),
                    write.bytes().to_owned(),
                ));
            }
        }

        Ok(loaded)
    }

    fn read_u64_at(segments: &[ImageSegmentContents<'static>], address: Address) -> Option<u64> {
        segments.iter().find_map(|segment| {
            let offset = segment.offset_of(address)?;
            segment.read_value::<u64>(offset)
        })
    }

    fn first_dir64_relocation(
        data: &BytesOrMapping<'_>,
    ) -> Result<(u64, u64, u64), Box<dyn std::error::Error>> {
        let pe = PeFile64::parse(data)?;
        let preferred_base = pe.relative_address_base();
        let mut blocks = pe
            .data_directories()
            .relocation_blocks(pe.data(), &pe.section_table())?
            .expect("base relocations");

        while let Some(block) = blocks.next()? {
            for reloc in block {
                if reloc.typ != IMAGE_REL_BASED_DIR64 {
                    continue;
                }

                let slot_address = preferred_base + reloc.virtual_address as u64;

                for section in pe.sections() {
                    let section_start = section.address();
                    let section_end = section_start + section.size();

                    if slot_address < section_start || slot_address + 8 > section_end {
                        continue;
                    }

                    let offset = (slot_address - section_start) as usize;
                    let bytes = section.data()?;
                    let value = u64::from_le_bytes(
                        bytes[offset..offset + 8]
                            .try_into()
                            .expect("8-byte relocation slot"),
                    );

                    return Ok((preferred_base, slot_address, value));
                }
            }
        }

        panic!("expected at least one IMAGE_REL_BASED_DIR64 relocation");
    }

    fn first_import_slot(
        data: &BytesOrMapping<'_>,
    ) -> Result<(String, u64), Box<dyn std::error::Error>> {
        let pe = PeFile64::parse(data)?;
        let preferred_base = pe.relative_address_base();
        let import_table = pe.import_table()?.expect("import table");
        let mut descriptors = import_table.descriptors()?;
        let descriptor = descriptors.next()?.expect("first import descriptor");
        let library =
            String::from_utf8_lossy(import_table.name(descriptor.name.get(LE))?).into_owned();
        let address_table = descriptor.first_thunk.get(LE);
        let lookup = {
            let original = descriptor.original_first_thunk.get(LE);
            if original == 0 {
                address_table
            } else {
                original
            }
        };
        let mut thunks = import_table.thunks(lookup)?;
        let thunk = thunks
            .next::<ImageNtHeaders64>()?
            .expect("first import thunk");

        let name = match import_table.import::<ImageNtHeaders64>(thunk)? {
            Import::Ordinal(ordinal) => format!("{library}!#{ordinal}"),
            Import::Name(_, name) => format!("{library}!{}", String::from_utf8_lossy(name)),
        };

        Ok((name, preferred_base + address_table as u64))
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_pe_exe() -> Result<(), Box<dyn std::error::Error>> {
        let pe = Pe::new(BytesOrMapping::from_file("tests/hello-pe.exe")?)?;
        let segments = load_segments(&pe)?;

        assert!(!segments.is_empty());
        assert!(pe.image_symbols().iter().next().is_some());
        assert!(!pe.extern_segment().is_empty());

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_pe_headers_default_disabled() -> Result<(), Box<dyn std::error::Error>> {
        let pe = Pe::new(BytesOrMapping::from_file("tests/hello-pe.exe")?)?;
        let mut segments = pe.image_segments();
        while let Some(segment) = segments.next()? {
            assert_ne!(segment.name(), "Headers");
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_pe_headers_enabled() -> Result<(), Box<dyn std::error::Error>> {
        let pe = Pe::new_with(
            BytesOrMapping::from_file("tests/hello-pe.exe")?,
            attributes![ATTRIBUTE_LOAD_HEADERS => true],
        )?;

        let mut header_address = None;
        let mut segments = pe.image_segments();
        while let Some(segment) = segments.next()? {
            if segment.name() == "Headers" {
                header_address = Some(segment.address().offset());
                assert!(segment.size() > 0);
            }
        }
        let header_address = header_address.expect("expected PE Headers segment");

        let mut saw_contents = false;
        let mut contents = pe.image_contents();
        while let Some(segment) = contents.next()? {
            if segment.address() == header_address {
                saw_contents = true;
                assert!(!segment.is_empty());
                break;
            }
        }

        assert!(saw_contents, "expected PE Headers contents");
        Ok(())
    }

    #[test]
    fn test_pe_header_read_failures_propagate() -> Result<(), Box<dyn std::error::Error>> {
        let data = BytesOrMapping::from_file("tests/hello-pe.exe")?;
        let fail = AtomicBool::new(false);
        let pe = PeFile64::parse(HeaderReadFailure {
            data: data.as_ref(),
            fail: &fail,
        })?;
        let imports = BTreeMap::new();
        let externs = ExternSegment::new(0u64, 1, ExternFunctionTemplate::new([0u8]));
        let region_bank = PeRegionBankMap::new();
        let config = PeLoaderProperties::LOAD_HEADERS;

        fail.store(true, Ordering::SeqCst);
        let mut contents = PeImageSegmentContents::new(
            &pe,
            Endian::Little,
            RawAddress::zero(),
            RawAddress::zero(),
            &imports,
            &externs,
            &region_bank,
            config,
        );
        assert!(contents.next().is_err());

        let last = RawAddress::from(<[u8]>::len(data.as_ref()).saturating_sub(1));
        let bank = ImageBank::new_in_default(RawAddress::zero()..=last);
        assert!(
            PeSegmentWalk::new(
                &pe,
                RawAddress::zero(),
                RawAddress::zero(),
                bank,
                &externs,
                config,
            )
            .is_err()
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_pe_custom_image_base() -> Result<(), Box<dyn std::error::Error>> {
        let data = BytesOrMapping::from_file("tests/hello-pe.exe")?;
        let (preferred_base, slot_address, original_value) = first_dir64_relocation(&data)?;
        let image_base = RawAddress::from(0x0001_8000_0000_u64);
        let pe = Pe::new_with(data, attributes![ATTRIBUTE_IMAGE_BASE => image_base])?;
        let segments = load_segments(&pe)?;
        let rebased_address = Address::in_default_space(
            image_base
                .offset()
                .wrapping_add(slot_address.wrapping_sub(preferred_base)),
        );
        let expected =
            original_value.wrapping_add(image_base.offset().wrapping_sub(preferred_base));
        let actual = read_u64_at(&segments, rebased_address).expect("rebased relocation slot");

        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_pe_import_slot_relocated_to_extern() -> Result<(), Box<dyn std::error::Error>> {
        let data = BytesOrMapping::from_file("tests/hello-pe.exe")?;
        let (symbol_name, slot_address) = first_import_slot(&data)?;
        let pe = Pe::new(data)?;
        let segments = load_segments(&pe)?;
        let expected = pe
            .image_symbols()
            .iter()
            .find_map(|(_, entry)| {
                (entry.symbol().as_str() == symbol_name).then_some(entry.address())
            })
            .expect("import symbol");
        let actual = read_u64_at(&segments, Address::from(slot_address)).expect("import slot");

        assert_eq!(actual, expected.offset().offset());

        Ok(())
    }

    #[test]
    fn test_pe_custom_image_base_without_relocations() {
        let image_base = RawAddress::from(0x0001_8000_0000_u64);
        let err = match Pe::new_with(
            BytesOrMapping::from_file("tests/hello-pe-fixed.exe").expect("fixture"),
            attributes![ATTRIBUTE_IMAGE_BASE => image_base],
        ) {
            Ok(_) => panic!("rebasing fixed image should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("base relocation directory"));
    }

    #[test]
    fn test_pe_image_base_near_max_overflow() {
        let image_base = RawAddress::from(u64::MAX - 0x1000);
        let err = match Pe::new_with(
            BytesOrMapping::from_file("tests/hello-pe.exe").expect("fixture"),
            attributes![ATTRIBUTE_IMAGE_BASE => image_base],
        ) {
            Ok(_) => panic!("loading near u64::MAX should overflow"),
            Err(err) => err,
        };

        assert!(matches!(err, LoaderError::AddressOverflow(_)));
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_pe_memory_dump() -> Result<(), Box<dyn std::error::Error>> {
        let path = "tests/135b5560b10894c9022d926a88210684eaeb0a541eeb3947ea50655df39471a0.bin";

        assert!(Pe::new(BytesOrMapping::from_file(path)?).is_err());

        let pe = Pe::new_with(
            BytesOrMapping::from_file(path)?,
            attributes![ATTRIBUTE_PERMISSIVE => true],
        )?;
        let _segments = load_segments(&pe)?;

        Ok(())
    }
}
