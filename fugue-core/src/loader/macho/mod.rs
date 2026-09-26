use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::OnceLock;
use std::{slice, vec};

use fallible_iterator::FallibleIterator;
use object::endian::Endianness;
use object::read::macho::{
    FatArch, MachHeader, MachOFatFile, MachOFatFile32, MachOFatFile64, MachOFile, MachOFile32,
    MachOFile64,
};
use object::{
    FileKind, Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, ReadRef,
    RelocationEncoding, RelocationKind, RelocationTarget, SectionIndex, SectionKind, SymbolKind,
    macho,
};
use smallvec::smallvec;

use crate::AnalysisData;
use crate::arch::Arch;
use crate::ir::{
    Endian, RawAddress, RawAddressRangeSet, Symbol, SymbolIndex, SymbolProperties,
    SymbolTableSelector, TransientSymbolTable,
};
use crate::lifter::{ContextHint, LanguageError, LanguageId};
use crate::loader::macho::extensions::ImageContext;
use crate::loader::{
    ExternalThunkLayout, ImageAddress, ImageBacking, ImageBank, ImageBankHandle, ImageBankLayout,
    ImageLayout, ImageSegment, ImageSegmentContents, ImageSegmentContentsIterator,
    ImageSegmentIterator, ImageSpace, ImageSpaceHandle, ImageSpaces, Loadable, LoadableFromBytes,
    LoadableFromFile, LoadableMetadata, LoaderError,
};
use crate::platform::{Format, OperatingSystem, Platform};
use crate::storage::segments::SegmentProperties;
use crate::storage::segments::mapping::SegmentMappingProvenance;
use crate::types::attributes::{ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_IMAGE_BASE};
use crate::types::{AttributeMap, BytesOrMapping};

pub mod extensions;

mod relocations;
pub use relocations::MachOSegmentRelocator;

pub const MACHO_SYMTAB_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(0);

pub const ATTRIBUTE_VARIANT: &str = "loader.macho.variant";

#[ouroboros::self_referencing]
struct MachOInner<'a> {
    data: BytesOrMapping<'a>,
    #[borrows(data)]
    #[covariant]
    loaded: MachOLoadedRepr<'this>,
}

pub enum MachOFileRepr<'data> {
    MachO32(MachOFile32<'data, Endianness, &'data [u8]>),
    MachO64(MachOFile64<'data, Endianness, &'data [u8]>),
}

macro_rules! with_macho {
    ($inner:expr, $var:ident | $body:expr) => {
        match $inner {
            MachOFileRepr::MachO32($var) => $body,
            MachOFileRepr::MachO64($var) => $body,
        }
    };
}

impl<'data> MachOFileRepr<'data> {
    fn parse(data: &'data [u8], attributes: &AttributeMap) -> Result<Self, LoaderError> {
        let data = match FileKind::parse(data).map_err(LoaderError::format)? {
            FileKind::MachOFat32 => {
                let fat = MachOFatFile32::parse(data).map_err(LoaderError::format)?;
                select_fat_data(&fat, data, attributes)?
            }
            FileKind::MachOFat64 => {
                let fat = MachOFatFile64::parse(data).map_err(LoaderError::format)?;
                select_fat_data(&fat, data, attributes)?
            }
            FileKind::MachO32 | FileKind::MachO64 => data,
            _ => return Err(LoaderError::format_with("input is not a Mach-O image")),
        };

        Self::parse_thin(data)
    }

    fn parse_thin(data: &'data [u8]) -> Result<Self, LoaderError> {
        match FileKind::parse(data).map_err(LoaderError::format)? {
            FileKind::MachO32 => Ok(Self::MachO32(
                MachOFile32::parse(data).map_err(LoaderError::format)?,
            )),
            FileKind::MachO64 => Ok(Self::MachO64(
                MachOFile64::parse(data).map_err(LoaderError::format)?,
            )),
            _ => Err(LoaderError::format_with(
                "Mach-O universal member is not a Mach-O image",
            )),
        }
    }

    pub(crate) fn machine(&self) -> u32 {
        with_macho!(self, macho | macho.macho_header().cputype(macho.endian()))
    }

    pub(crate) fn subtype(&self) -> u32 {
        with_macho!(
            self,
            macho | macho.macho_header().cpusubtype(macho.endian())
        )
    }

    pub(crate) fn endian(&self) -> Endian {
        if with_macho!(self, macho | macho.is_little_endian()) {
            Endian::Little
        } else {
            Endian::Big
        }
    }

    pub(crate) fn is_64(&self) -> bool {
        with_macho!(self, macho | macho.is_64())
    }

    pub(crate) fn flags(&self) -> u32 {
        with_macho!(self, macho | macho.macho_header().flags(macho.endian()))
    }

    pub(crate) fn file_type(&self) -> u32 {
        with_macho!(self, macho | macho.macho_header().filetype(macho.endian()))
    }

    fn language_id(&self) -> Option<LanguageId> {
        let (processor, bits) = match self.machine() {
            macho::CPU_TYPE_ARM => ("ARM", 32),
            macho::CPU_TYPE_ARM64 => ("AARCH64", 64),
            macho::CPU_TYPE_ARM64_32 => ("AARCH64", 32),
            macho::CPU_TYPE_MIPS => ("MIPS", 32),
            macho::CPU_TYPE_POWERPC => ("PowerPC", 32),
            macho::CPU_TYPE_POWERPC64 => ("PowerPC", 64),
            macho::CPU_TYPE_X86 => ("x86", 32),
            macho::CPU_TYPE_X86_64 => ("x86", 64),
            _ => return None,
        };

        Some(LanguageId::new(processor, self.endian().is_big(), bits))
    }

    fn entry(&self) -> Result<Option<RawAddress>, LoaderError> {
        with_macho!(self, macho | macho_entry(macho))
    }
}

fn select_fat_data<'data, Fat>(
    fat: &MachOFatFile<'data, Fat>,
    data: &'data [u8],
    attributes: &AttributeMap,
) -> Result<&'data [u8], LoaderError>
where
    Fat: FatArch,
{
    let Some(requested) = attributes.get_attr::<String>(ATTRIBUTE_VARIANT) else {
        let arch = fat
            .arches()
            .first()
            .ok_or_else(|| LoaderError::format_with("Mach-O universal image has no members"))?;
        return arch.data(data).map_err(LoaderError::format);
    };

    let requested = requested
        .parse::<LanguageId>()
        .map_err(LanguageError::from)?;
    for arch in fat.arches() {
        let candidate = arch.data(data).map_err(LoaderError::format)?;
        let view = MachOFileRepr::parse_thin(candidate)?;
        let Some(id) = view.language_id() else {
            continue;
        };
        if id.processor() == requested.processor()
            && id.is_big_endian() == requested.is_big_endian()
            && id.bits() == requested.bits()
        {
            return Ok(candidate);
        }
    }

    Err(LoaderError::other_with(format!(
        "Mach-O universal variant `{requested}` is not present"
    )))
}

fn macho_entry<'data, Mach, R>(
    macho: &MachOFile<'data, Mach, R>,
) -> Result<Option<RawAddress>, LoaderError>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    let mut commands = macho.macho_load_commands().map_err(LoaderError::format)?;
    while let Some(command) = commands.next().map_err(LoaderError::format)? {
        let Some(entry) = command.entry_point().map_err(LoaderError::format)? else {
            continue;
        };
        let file_offset = entry.entryoff.get(macho.endian());
        for segment in macho.segments() {
            let (offset, size) = segment.file_range();
            let Some(last) = offset.checked_add(size) else {
                continue;
            };
            if file_offset >= offset && file_offset < last {
                let address = segment
                    .address()
                    .checked_add(file_offset - offset)
                    .ok_or_else(|| LoaderError::address_overflow(segment.address()))?;
                return Ok(Some(RawAddress::from(address)));
            }
        }
        return Err(LoaderError::format_with(
            "Mach-O entry point is outside every segment",
        ));
    }

    let entry = macho.entry();
    Ok((entry != 0).then(|| RawAddress::from(entry)))
}

struct MachOLoadedRepr<'data> {
    view: MachOFileRepr<'data>,
    state: MachOLoadState,
}

impl<'data> MachOLoadedRepr<'data> {
    fn parse(data: &'data [u8], attributes: &AttributeMap) -> Result<Self, LoaderError> {
        let view = MachOFileRepr::parse(data, attributes)?;
        let state = MachOLoadState::from_view(&view, attributes)?;
        Ok(Self { view, state })
    }
}

#[derive(AnalysisData)]
pub struct MachO<'a> {
    object: MachOInner<'a>,
    metadata: OnceLock<LoadableMetadata>,
    path: Option<String>,
    attributes: AttributeMap,
}

impl<'a> MachO<'a> {
    pub fn new(data: impl Into<BytesOrMapping<'a>>) -> Result<Self, LoaderError> {
        Self::new_with(data, AttributeMap::new())
    }

    pub fn new_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        let attributes = attributes.into();
        let object = MachOInner::try_new(data.into(), |data| {
            MachOLoadedRepr::parse(data.as_ref(), &attributes)
        })?;
        let mut slf = Self {
            object,
            metadata: OnceLock::new(),
            path: None,
            attributes,
        };

        if let Some(entry) = slf.entry() {
            slf.attributes.set_attr(ATTRIBUTE_ENTRY_POINT, entry);
        }

        Ok(slf)
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

    pub fn loaded_view(&self) -> &MachOFileRepr<'_> {
        &self.object.borrow_loaded().view
    }

    pub fn mapping_hints(&self) -> &BTreeMap<RawAddress, ContextHint> {
        &self.object.borrow_loaded().state.mapping_hints
    }

    pub fn image_symbols(&self) -> &TransientSymbolTable<ImageAddress> {
        &self.object.borrow_loaded().state.symbols
    }

    pub fn external_thunks(&self) -> &ExternalThunkLayout {
        &self.object.borrow_loaded().state.external_thunks
    }

    pub fn base_address(&self) -> RawAddress {
        self.object.borrow_loaded().state.base
    }

    pub fn is_object(&self) -> bool {
        self.object.borrow_loaded().state.is_object
    }

    pub fn entry(&self) -> Option<RawAddress> {
        self.object
            .borrow_loaded()
            .state
            .entry
            .map(|entry| entry.offset())
    }

    pub fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Macos
    }
}

struct MachOLoadState {
    architecture: Arch,
    base: RawAddress,
    preferred_base: RawAddress,
    entry: Option<ImageAddress>,
    layout: ImageLayout,
    mapping_hints: BTreeMap<RawAddress, ContextHint>,
    symbols: TransientSymbolTable<ImageAddress>,
    segments: Vec<MachOImageSegment>,
    external_thunks: ExternalThunkLayout,
    is_object: bool,
}

impl MachOLoadState {
    fn from_view(view: &MachOFileRepr<'_>, attributes: &AttributeMap) -> Result<Self, LoaderError> {
        let is_object = with_macho!(view, macho | macho.kind() == ObjectKind::Relocatable);
        let preferred_base = if is_object {
            RawAddress::zero()
        } else {
            with_macho!(
                view,
                macho
                    | macho
                        .segments()
                        .filter(macho_segment_is_loadable)
                        .map(|segment| segment.address())
                        .min()
                        .map(RawAddress::from)
                        .unwrap_or_default()
            )
        };
        let base = attributes
            .get_attr::<RawAddress>(ATTRIBUTE_IMAGE_BASE)
            .unwrap_or(preferred_base);

        if !is_object && base != preferred_base {
            return Err(LoaderError::other_with(
                "cannot rebase a linked Mach-O image",
            ));
        }

        let entry = view.entry()?.and_then(|entry| {
            entry
                .checked_sub(preferred_base)
                .and_then(|offset| base.checked_add(offset))
        });
        let context = ImageContext::new(view, base, preferred_base, entry, attributes);
        let architecture = context.resolve_architecture()?;

        let MachOSymbolLayout {
            bounds,
            symbols,
            sections,
            external_thunks,
        } = with_macho!(
            view,
            macho | MachOSymbolLayout::from_macho(macho, &architecture, base, preferred_base,)?
        );

        let default_bank = ImageBank::new_in_default(bounds.clone());
        let (segments, spaces, bank_layout) = with_macho!(
            view,
            macho | {
                let mut walk = MachOSegmentWalk::new(
                    macho,
                    base,
                    preferred_base,
                    default_bank,
                    &sections,
                    &external_thunks,
                    is_object,
                )?;
                let mut segments = Vec::new();
                while let Some(segment) = walk.next_segment()? {
                    segments.push(segment);
                }
                let (spaces, bank_layout) = walk.into_parts();
                (segments, spaces, bank_layout)
            }
        );
        let (banks, _) = bank_layout.into_parts();
        let layout = ImageLayout::new(banks, spaces);
        let mut image_symbols = TransientSymbolTable::new();
        for (index, symbol) in symbols {
            let space = segments
                .iter()
                .find(|segment| {
                    let start = segment.address.offset();
                    start
                        .checked_add(segment.size.saturating_sub(1))
                        .is_some_and(|last| symbol.address >= start && symbol.address <= last)
                })
                .map(MachOImageSegment::space)
                .unwrap_or_default();
            image_symbols.insert(
                index,
                ImageAddress::new(space, symbol.address),
                symbol.symbol,
                symbol.properties,
            );
        }

        Ok(Self {
            architecture,
            base,
            preferred_base,
            entry: entry.map(ImageAddress::in_default_space),
            layout,
            mapping_hints: BTreeMap::new(),
            symbols: image_symbols,
            segments,
            external_thunks,
            is_object,
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct MachOSectionMap(Vec<Option<RawAddress>>);

impl MachOSectionMap {
    fn new() -> Self {
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

struct RawMachOSymbol {
    address: RawAddress,
    symbol: Symbol,
    properties: SymbolProperties,
}

struct MachOSymbolLayout {
    bounds: RangeInclusive<RawAddress>,
    symbols: BTreeMap<SymbolIndex, RawMachOSymbol>,
    sections: MachOSectionMap,
    external_thunks: ExternalThunkLayout,
}

impl MachOSymbolLayout {
    fn from_macho<'data>(
        macho: &'data impl Object<'data>,
        architecture: &Arch,
        base: RawAddress,
        preferred_base: RawAddress,
    ) -> Result<Self, LoaderError> {
        let is_object = macho.kind() == ObjectKind::Relocatable;
        let mut sections = MachOSectionMap::new();
        let mut minimum = base;
        let mut next = base;

        if is_object {
            for section in macho.sections().filter(macho_section_is_loadable) {
                let alignment = usize::try_from(section.align().max(1))
                    .map_err(|_| LoaderError::address_overflow(next))?;
                let address = next.align(alignment);
                if address < next {
                    return Err(LoaderError::address_overflow(next));
                }
                sections.insert(section.index().0, address);
                next = address
                    .checked_add(section.size())
                    .ok_or_else(|| LoaderError::address_overflow(address))?;
            }
        } else {
            let slide = base - preferred_base;
            let mut found = false;
            for segment in macho.segments().filter(macho_segment_is_loadable) {
                let address = slide
                    .checked_add(segment.address())
                    .ok_or_else(|| LoaderError::address_overflow(base))?;
                let end = address
                    .checked_add(segment.size())
                    .ok_or_else(|| LoaderError::address_overflow(address))?;
                minimum = if found { minimum.min(address) } else { address };
                next = if found { next.max(end) } else { end };
                found = true;
            }
            if !found {
                next = base;
            }
        }

        let alignment = architecture
            .language()
            .address_alignment()
            .max(architecture.language().address_size());
        let external_base = next.align(alignment);
        if external_base < next {
            return Err(LoaderError::address_overflow(next));
        }
        let mut external_thunks = ExternalThunkLayout::new(
            external_base,
            alignment,
            architecture.external_thunk_template(),
        );
        let mut symbols = BTreeMap::new();
        let function_symbols = macho
            .sections()
            .flat_map(|section| section.relocations())
            .filter_map(|(_, relocation)| {
                let is_function = matches!(
                    relocation.kind(),
                    RelocationKind::GotRelative | RelocationKind::PltRelative
                ) || matches!(
                    relocation.encoding(),
                    RelocationEncoding::AArch64Call | RelocationEncoding::X86Branch
                );
                let RelocationTarget::Symbol(index) = relocation.target() else {
                    return None;
                };
                is_function.then_some(index.0)
            })
            .collect::<BTreeSet<usize>>();

        for symbol in macho.symbols() {
            let mut properties = macho_symbol_properties(&symbol);
            if function_symbols.contains(&symbol.index().0) {
                properties.remove(SymbolProperties::DATA);
                properties.insert(SymbolProperties::FUNCTION);
            } else if !properties.intersects(SymbolProperties::FUNCTION | SymbolProperties::DATA)
                && let Some(index) = symbol.section_index()
                && let Ok(section) = macho.section_by_index(index)
            {
                let kind = if macho_section_properties(&section).is_executable() {
                    SymbolProperties::FUNCTION
                } else {
                    SymbolProperties::DATA
                };
                properties.insert(kind);
            }
            let address = if symbol.is_undefined() && symbol.is_global() {
                external_thunks
                    .allocate()
                    .ok_or_else(|| LoaderError::address_overflow(external_base))?
            } else if let Some(index) = symbol.section_index() {
                if is_object {
                    let Some(section_start) = sections.get(index.0) else {
                        continue;
                    };
                    let section = macho.section_by_index(index).map_err(LoaderError::format)?;
                    let offset = symbol.address().saturating_sub(section.address());
                    section_start
                        .checked_add(offset)
                        .ok_or_else(|| LoaderError::address_overflow(section_start))?
                } else {
                    (base - preferred_base)
                        .checked_add(symbol.address())
                        .ok_or_else(|| LoaderError::address_overflow(base))?
                }
            } else if symbol.address() != 0 {
                (base - preferred_base)
                    .checked_add(symbol.address())
                    .ok_or_else(|| LoaderError::address_overflow(base))?
            } else {
                continue;
            };

            symbols.insert(
                SymbolIndex::new(MACHO_SYMTAB_SELECTOR, symbol.index().0),
                RawMachOSymbol {
                    address,
                    symbol: symbol.name().ok().unwrap_or_default().into(),
                    properties,
                },
            );
        }

        let last = external_thunks
            .last()
            .or_else(|| next.checked_sub(1usize))
            .ok_or(LoaderError::EmptyImage)?;
        minimum = minimum.min(external_thunks.start());

        Ok(Self {
            bounds: minimum..=last,
            symbols,
            sections,
            external_thunks,
        })
    }
}

fn macho_symbol_properties<'data>(symbol: &impl ObjectSymbol<'data>) -> SymbolProperties {
    let kind = match symbol.kind() {
        SymbolKind::Text | SymbolKind::Label => SymbolProperties::FUNCTION,
        SymbolKind::Data | SymbolKind::Tls => SymbolProperties::DATA,
        _ => SymbolProperties::NONE,
    };
    let visibility = if symbol.is_undefined() && symbol.is_global() {
        SymbolProperties::EXTERN
    } else if symbol.is_global() {
        SymbolProperties::LOCAL | SymbolProperties::EXPORT
    } else {
        SymbolProperties::LOCAL
    };
    kind | visibility
}

fn macho_section_is_loadable<'data>(section: &impl ObjectSection<'data>) -> bool {
    section.size() != 0
        && !matches!(
            section.kind(),
            SectionKind::Debug
                | SectionKind::Linker
                | SectionKind::Metadata
                | SectionKind::Other
                | SectionKind::OtherString
        )
}

pub(crate) fn macho_object_section_address<'data>(
    macho: &'data impl Object<'data>,
    base: RawAddress,
    target: usize,
) -> Option<RawAddress> {
    let mut next = base;
    for section in macho.sections().filter(macho_section_is_loadable) {
        let alignment = usize::try_from(section.align().max(1)).ok()?;
        let address = next.align(alignment);
        if address < next {
            return None;
        }
        if section.index().0 == target {
            return Some(address);
        }
        next = address.checked_add(section.size())?;
    }
    None
}

fn macho_segment_is_loadable<'data>(segment: &impl ObjectSegment<'data>) -> bool {
    if segment.size() == 0 {
        return false;
    }
    let permissions = segment.permissions();
    let (_, file_size) = segment.file_range();
    permissions.readable() || permissions.writable() || permissions.executable() || file_size != 0
}

fn macho_section_properties<'data>(section: &impl ObjectSection<'data>) -> SegmentProperties {
    let mut properties = SegmentProperties::PERM_READ;
    let segment = section.segment_name().ok().flatten().unwrap_or_default();
    match segment {
        "__TEXT" => properties.insert(SegmentProperties::PERM_EXECUTE),
        "__DATA" | "__DATA_DIRTY" => properties.insert(SegmentProperties::PERM_WRITE),
        _ => {}
    }
    if section.kind().is_bss() || matches!(section.file_range(), None | Some((_, 0))) {
        properties.insert(SegmentProperties::UNINITIALISED);
    }
    properties
}

fn macho_segment_properties<'data>(segment: &impl ObjectSegment<'data>) -> SegmentProperties {
    let permissions = segment.permissions();
    let mut properties = SegmentProperties::empty();
    if permissions.readable() {
        properties.insert(SegmentProperties::PERM_READ);
    }
    if permissions.writable() {
        properties.insert(SegmentProperties::PERM_WRITE);
    }
    if permissions.executable() {
        properties.insert(SegmentProperties::PERM_EXECUTE);
    }
    if segment.file_range().1 < segment.size() {
        properties.insert(SegmentProperties::UNINITIALISED);
    }
    properties
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MachORegionSourceKind {
    Section,
    Segment,
    External,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MachORegionSource {
    kind: MachORegionSourceKind,
    index: usize,
}

impl MachORegionSource {
    fn new(kind: MachORegionSourceKind, index: usize) -> Self {
        Self { kind, index }
    }

    fn section(index: usize) -> Self {
        Self::new(MachORegionSourceKind::Section, index)
    }

    fn segment(index: usize) -> Self {
        Self::new(MachORegionSourceKind::Segment, index)
    }

    fn external_thunks() -> Self {
        Self::new(MachORegionSourceKind::External, 0)
    }
}

struct MachORegion {
    name: String,
    address: RawAddress,
    size: u64,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
    source: MachORegionSource,
}

struct MachOImageSegment {
    name: String,
    address: ImageAddress,
    backing_offset: RawAddress,
    size: u64,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
    source: MachORegionSource,
    bank: ImageBankHandle,
}

impl MachOImageSegment {
    fn new(region: &MachORegion, space: ImageSpaceHandle, backing_offset: RawAddress) -> Self {
        Self {
            name: region.name.clone(),
            address: ImageAddress::new(space, region.address),
            backing_offset,
            size: region.size,
            properties: region.properties,
            provenance: region.provenance,
            source: region.source,
            bank: ImageBankHandle::default(),
        }
    }

    fn space(&self) -> ImageSpaceHandle {
        self.address.space()
    }
}

type MachOBankLayout = ImageBankLayout<MachORegionSource>;

struct MachOSegmentWalk<'file> {
    regions: vec::IntoIter<MachORegion>,
    external_thunks: Option<&'file ExternalThunkLayout>,
    bank_base: RawAddress,
    base_space: ImageSpaceHandle,
    covered: RawAddressRangeSet,
    spaces: ImageSpaces,
    bank_layout: MachOBankLayout,
}

impl<'file> MachOSegmentWalk<'file> {
    fn new<'data>(
        macho: &'data impl Object<'data>,
        base: RawAddress,
        preferred_base: RawAddress,
        default_bank: ImageBank,
        sections: &MachOSectionMap,
        external_thunks: &'file ExternalThunkLayout,
        is_object: bool,
    ) -> Result<Self, LoaderError> {
        let base_space = ImageSpaceHandle::default();
        let bank_base = *default_bank.range().start();
        let mut regions = Vec::new();
        if is_object {
            for section in macho.sections().filter(macho_section_is_loadable) {
                let Some(address) = sections.get(section.index().0) else {
                    continue;
                };
                let segment_name = section.segment_name().ok().flatten().unwrap_or_default();
                let section_name = section.name().ok().unwrap_or("LOAD");
                let name = if segment_name.is_empty() {
                    section_name.to_owned()
                } else {
                    format!("{segment_name},{section_name}")
                };
                regions.push(MachORegion {
                    name,
                    address,
                    size: section.size(),
                    properties: macho_section_properties(&section),
                    provenance: SegmentMappingProvenance::Section,
                    source: MachORegionSource::section(section.index().0),
                });
            }
        } else {
            let slide = base - preferred_base;
            for (ordinal, segment) in macho.segments().enumerate() {
                if !macho_segment_is_loadable(&segment) {
                    continue;
                }
                let address = slide
                    .checked_add(segment.address())
                    .ok_or_else(|| LoaderError::address_overflow(base))?;
                regions.push(MachORegion {
                    name: segment.name().ok().flatten().unwrap_or("LOAD").to_owned(),
                    address,
                    size: segment.size(),
                    properties: macho_segment_properties(&segment),
                    provenance: SegmentMappingProvenance::Segment,
                    source: MachORegionSource::segment(ordinal),
                });
            }
        }

        Ok(Self {
            regions: regions.into_iter(),
            external_thunks: Some(external_thunks),
            bank_base,
            base_space,
            covered: RawAddressRangeSet::new(),
            spaces: smallvec![ImageSpace::base(base_space)],
            bank_layout: MachOBankLayout::new(default_bank),
        })
    }

    fn next_region(&mut self) -> Option<MachORegion> {
        self.regions.next().or_else(|| self.external_region())
    }

    fn external_region(&mut self) -> Option<MachORegion> {
        let external_thunks = self
            .external_thunks
            .take()
            .filter(|layout| !layout.is_empty())?;
        Some(MachORegion {
            name: "EXTERNAL".to_owned(),
            address: external_thunks.start(),
            size: external_thunks.size() as u64,
            properties: SegmentProperties::PERM_READ | SegmentProperties::PERM_EXECUTE,
            provenance: SegmentMappingProvenance::External,
            source: MachORegionSource::external_thunks(),
        })
    }

    fn next_segment(&mut self) -> Result<Option<MachOImageSegment>, LoaderError> {
        let Some(region) = self.next_region() else {
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
            self.bank_layout.route_region(region.source, bank);
            (handle, bank, RawAddress::zero())
        } else {
            (self.base_space, ImageBankHandle::default(), backing_offset)
        };
        self.covered.insert_range(range);

        let mut segment = MachOImageSegment::new(&region, space, backing_offset);
        segment.bank = bank;
        Ok(Some(segment))
    }

    fn into_parts(self) -> (ImageSpaces, MachOBankLayout) {
        (self.spaces, self.bank_layout)
    }
}

struct MachOImageSegments<'a> {
    segments: slice::Iter<'a, MachOImageSegment>,
    symbols: &'a TransientSymbolTable<ImageAddress>,
    mapping_hints: &'a BTreeMap<RawAddress, ContextHint>,
}

impl<'a> MachOImageSegments<'a> {
    fn new(
        segments: &'a [MachOImageSegment],
        symbols: &'a TransientSymbolTable<ImageAddress>,
        mapping_hints: &'a BTreeMap<RawAddress, ContextHint>,
    ) -> Self {
        Self {
            segments: segments.iter(),
            symbols,
            mapping_hints,
        }
    }

    fn image_segment(&self, segment: &'a MachOImageSegment) -> ImageSegment<'a> {
        let start = segment.address.offset();
        let (mapping_hints, function_hints) = start
            .checked_add(segment.size.saturating_sub(1))
            .map(|last| {
                let mapping_hints = self
                    .mapping_hints
                    .range(start..=last)
                    .map(|(address, hint)| (*address, hint.clone()))
                    .collect::<BTreeMap<RawAddress, ContextHint>>();
                let function_hints = self
                    .symbols
                    .range_by_address(
                        segment.address..=ImageAddress::new(segment.address.space(), last),
                    )
                    .filter(|(_, symbol)| {
                        symbol
                            .properties()
                            .contains(SymbolProperties::FUNCTION | SymbolProperties::EXTERN)
                    })
                    .map(|(_, symbol)| symbol.address().offset())
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

impl<'a> FallibleIterator for MachOImageSegments<'a> {
    type Error = LoaderError;
    type Item = ImageSegment<'a>;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        let Some(segment) = self.segments.next() else {
            return Ok(None);
        };
        Ok(Some(self.image_segment(segment)))
    }
}

struct MachOImageContext<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    macho: &'file MachOFile<'data, Mach, R>,
    arch: &'file Arch,
    symbols: &'file TransientSymbolTable<ImageAddress>,
    external_thunks: &'file ExternalThunkLayout,
    is_object: bool,
}

impl<'data, 'file, Mach, R> MachOImageContext<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn new(
        macho: &'file MachOFile<'data, Mach, R>,
        arch: &'file Arch,
        symbols: &'file TransientSymbolTable<ImageAddress>,
        external_thunks: &'file ExternalThunkLayout,
        is_object: bool,
    ) -> Self {
        Self {
            macho,
            arch,
            symbols,
            external_thunks,
            is_object,
        }
    }

    fn macho(&self) -> &'file MachOFile<'data, Mach, R> {
        self.macho
    }

    fn arch(&self) -> &'file Arch {
        self.arch
    }

    fn symbols(&self) -> &'file TransientSymbolTable<ImageAddress> {
        self.symbols
    }

    fn external_thunks(&self) -> &'file ExternalThunkLayout {
        self.external_thunks
    }

    fn is_object(&self) -> bool {
        self.is_object
    }
}

struct MachOImageSegmentContents<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    context: MachOImageContext<'data, 'file, Mach, R>,
    segments: slice::Iter<'file, MachOImageSegment>,
    current_base: RawAddress,
    preferred_base: RawAddress,
}

impl<'data, 'file, Mach, R> MachOImageSegmentContents<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn new(
        context: MachOImageContext<'data, 'file, Mach, R>,
        current_base: RawAddress,
        preferred_base: RawAddress,
        segments: &'file [MachOImageSegment],
    ) -> Self {
        Self {
            context,
            segments: segments.iter(),
            current_base,
            preferred_base,
        }
    }

    fn relocator(&self) -> MachOSegmentRelocator<'data, 'file, Mach, R> {
        MachOSegmentRelocator::new(
            self.context.macho(),
            self.context.arch(),
            self.current_base,
            self.preferred_base,
            self.context.symbols(),
            self.context.is_object(),
        )
    }

    fn external_thunk_contents(&self, segment: &MachOImageSegment) -> ImageSegmentContents<'data> {
        let thunks = self.context.external_thunks();
        let padding = thunks.aligned_template_size() - thunks.template().size();
        let functions = self
            .context
            .symbols()
            .iter()
            .filter_map(|(_, symbol)| {
                symbol
                    .properties()
                    .contains(SymbolProperties::FUNCTION | SymbolProperties::EXTERN)
                    .then_some(symbol.address().offset())
            })
            .collect::<BTreeSet<RawAddress>>();
        let mut data = Vec::with_capacity(thunks.size());
        for address in thunks.iter() {
            if functions.contains(&address) {
                data.extend_from_slice(thunks.template().bytes());
                data.resize(data.len() + padding, 0);
            } else {
                data.resize(data.len() + thunks.aligned_template_size(), 0);
            }
        }

        let mut contents = ImageSegmentContents::new_in_bank(
            segment.bank,
            segment.address.offset(),
            self.context.arch().endian(),
            Cow::Owned(data),
        );
        for address in functions {
            contents.add_function_hint(address);
        }
        contents
    }
}

impl<'data, 'file, Mach, R> FallibleIterator for MachOImageSegmentContents<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    type Error = LoaderError;
    type Item = ImageSegmentContents<'data>;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        let Some(segment) = self.segments.next() else {
            return Ok(None);
        };

        let mut contents = match segment.source.kind {
            MachORegionSourceKind::External => {
                return Ok(Some(self.external_thunk_contents(segment)));
            }
            MachORegionSourceKind::Section => {
                let section = self
                    .context
                    .macho()
                    .section_by_index(SectionIndex(segment.source.index))
                    .expect("Mach-O section source index must be valid");
                let data = section.data().map_err(LoaderError::format)?;
                let emit = data
                    .len()
                    .min(usize::try_from(segment.size).unwrap_or(usize::MAX));
                let mut contents = ImageSegmentContents::new_sparse_in_bank(
                    segment.bank,
                    segment.address.offset(),
                    self.context.arch().endian(),
                    &data[..emit],
                    segment.size,
                );
                self.relocator().apply(&mut contents)?;
                contents
            }
            MachORegionSourceKind::Segment => {
                let raw = self
                    .context
                    .macho()
                    .segments()
                    .nth(segment.source.index)
                    .expect("Mach-O segment source index must be valid");
                let data = raw.data().map_err(LoaderError::format)?;
                let emit = data
                    .len()
                    .min(usize::try_from(segment.size).unwrap_or(usize::MAX));
                let mut contents = ImageSegmentContents::new_sparse_in_bank(
                    segment.bank,
                    segment.address.offset(),
                    self.context.arch().endian(),
                    &data[..emit],
                    segment.size,
                );
                self.relocator().apply(&mut contents)?;
                contents
            }
        };
        if let Some(last) = segment
            .address
            .offset()
            .checked_add(segment.size.saturating_sub(1))
        {
            for (_, symbol) in self.context.symbols().range_by_address(
                segment.address..=ImageAddress::new(segment.address.space(), last),
            ) {
                if symbol.properties().contains(SymbolProperties::FUNCTION) {
                    contents.add_function_hint(symbol.address().offset());
                }
            }
        }
        Ok(Some(contents))
    }
}

impl<'a> LoadableFromBytes<'a> for MachO<'a> {
    fn from_bytes_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        Self::new_with(data, attributes)
    }
}

impl LoadableFromFile for MachO<'_> {
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

impl Loadable for MachO<'_> {
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
                format!("Fugue v{} Mach-O Loader", env!("CARGO_PKG_VERSION")),
            )
        })
    }

    fn architecture(&self) -> Arch {
        self.object.borrow_loaded().state.architecture.clone()
    }

    fn platform(&self) -> Platform {
        self.architecture()
            .platform()
            .with_format(Format::MachO)
            .with_os(self.operating_system())
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
        Box::new(MachOImageSegments::new(
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
        let state = &loaded.state;
        with_macho!(
            &loaded.view,
            macho | {
                let context = MachOImageContext::new(
                    macho,
                    &state.architecture,
                    &state.symbols,
                    &state.external_thunks,
                    state.is_object,
                );
                Box::new(MachOImageSegmentContents::new(
                    context,
                    state.base,
                    state.preferred_base,
                    &state.segments,
                )) as ImageSegmentContentsIterator<'b>
            }
        )
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicBool, Ordering};

    use fallible_iterator::FallibleIterator;
    use object::{
        Object, ObjectSection, RelocationEncoding, RelocationKind, RelocationTarget, macho,
    };

    use super::*;
    use crate::attributes;
    use crate::loader::{
        ATTRIBUTE_MACHO_VARIANT, Loadable, Loader, MachORelocationContext, MachORelocationExtension,
    };

    const ARM64_OBJECT: &str = "tests/hello-macho-arm64.o";
    const I386_OBJECT: &str = "tests/hello-macho-i386.o";
    const UNIVERSAL_EXECUTABLE: &str = "tests/hello-macho-universal.macho";
    const UNIVERSAL_OBJECT: &str = "tests/hello-macho-universal.o";
    const X86_64_EXECUTABLE: &str = "tests/hello-macho-x86_64.macho";
    const X86_64_OBJECT: &str = "tests/hello-macho-x86_64.o";

    static RELOCATION_EXTENSION_USED: AtomicBool = AtomicBool::new(false);

    fn test_relocation_extension(
        context: &mut MachORelocationContext<'_, '_>,
    ) -> Result<bool, LoaderError> {
        if context.machine() != macho::CPU_TYPE_X86_64
            || context.base() != RawAddress::from(0x4000u64)
            || context.relocation_type() != macho::X86_64_RELOC_UNSIGNED
        {
            return Ok(false);
        }

        let offset = context.offset();
        context
            .segment_mut()
            .write_value(offset, 0x1234_5678_9abc_def0u64);
        RELOCATION_EXTENSION_USED.store(true, Ordering::SeqCst);
        Ok(true)
    }

    crate::extension::submit! {
        MachORelocationExtension::new("macho-test-relocation", test_relocation_extension)
    }

    #[test]
    fn thin_32_and_64_images_load() -> Result<(), LoaderError> {
        let i386 = MachO::from_file(I386_OBJECT)?;
        assert!(!i386.loaded_view().is_64());
        assert_eq!(i386.loaded_view().machine(), macho::CPU_TYPE_X86);

        let x86_64 = MachO::from_file(X86_64_OBJECT)?;
        assert!(x86_64.loaded_view().is_64());
        assert_eq!(x86_64.loaded_view().machine(), macho::CPU_TYPE_X86_64);

        Ok(())
    }

    #[test]
    fn universal_defaults_to_first_member() -> Result<(), LoaderError> {
        let macho = MachO::from_file(UNIVERSAL_OBJECT)?;
        assert_eq!(macho.loaded_view().machine(), macho::CPU_TYPE_X86_64);
        Ok(())
    }

    #[test]
    fn universal_selects_configured_members() -> Result<(), LoaderError> {
        let x86_64 = MachO::from_file_with(
            UNIVERSAL_OBJECT,
            attributes![ATTRIBUTE_MACHO_VARIANT => "x86:LE:64"],
        )?;
        assert_eq!(x86_64.loaded_view().machine(), macho::CPU_TYPE_X86_64);

        let arm64 = MachO::from_file_with(
            UNIVERSAL_OBJECT,
            attributes![ATTRIBUTE_MACHO_VARIANT => "AARCH64:LE:64"],
        )?;
        assert_eq!(arm64.loaded_view().machine(), macho::CPU_TYPE_ARM64);

        Ok(())
    }

    #[test]
    fn universal_rejects_missing_member() {
        let result = MachO::from_file_with(
            UNIVERSAL_OBJECT,
            attributes![ATTRIBUTE_MACHO_VARIANT => "PowerPC:BE:32"],
        );
        assert!(matches!(result, Err(LoaderError::Other(_))));
    }

    #[test]
    fn universal_rejects_invalid_variant() {
        let result = MachO::from_file_with(
            UNIVERSAL_OBJECT,
            attributes![ATTRIBUTE_MACHO_VARIANT => "x86:LE"],
        );
        assert!(matches!(result, Err(LoaderError::Language(_))));
    }

    #[test]
    fn relocatable_section_layout_and_contents_load() -> Result<(), LoaderError> {
        let macho = MachO::from_file(X86_64_OBJECT)?;
        let mut segments = macho.image_segments();
        let segment = segments
            .next()?
            .expect("Mach-O fixture must contain a section");
        assert_eq!(segment.provenance(), SegmentMappingProvenance::Section);

        let mut contents = macho.image_contents();
        let contents = contents
            .next()?
            .expect("Mach-O fixture must contain section contents");
        assert_eq!(contents.address(), segment.address().offset());
        assert_eq!(contents.size(), segment.size());
        assert!(!contents.is_empty());

        Ok(())
    }

    #[test]
    fn linked_segment_and_entry_point_load() -> Result<(), LoaderError> {
        let macho = MachO::from_file(X86_64_EXECUTABLE)?;
        assert!(!macho.is_object());
        assert!(macho.entry().is_some());

        let mut segments = macho.image_segments();
        let mut found_segment = false;
        while let Some(segment) = segments.next()? {
            if segment.provenance() == SegmentMappingProvenance::Segment {
                found_segment = true;
                break;
            }
        }
        assert!(found_segment);

        let mut contents = macho.image_contents();
        assert!(contents.next()?.is_some());

        Ok(())
    }

    #[test]
    fn linked_image_rejects_changed_base() {
        let result = MachO::from_file_with(
            X86_64_EXECUTABLE,
            attributes![ATTRIBUTE_IMAGE_BASE => 0x2_0000_0000u64],
        );
        assert!(matches!(result, Err(LoaderError::Other(_))));
    }

    #[test]
    fn generic_relocation_uses_sized_write() -> Result<(), LoaderError> {
        let macho = MachO::from_file(X86_64_OBJECT)?;
        let (patch, target) = with_macho!(
            macho.loaded_view(),
            file | {
                file.sections()
                    .find_map(|section| {
                        let address = macho_object_section_address(
                            file,
                            macho.base_address(),
                            section.index().0,
                        )?;
                        section.relocations().find_map(|(offset, relocation)| {
                            if relocation.kind() != RelocationKind::Absolute
                                || relocation.size() != 64
                            {
                                return None;
                            }
                            let RelocationTarget::Symbol(index) = relocation.target() else {
                                return None;
                            };
                            let (_, symbol) = macho
                                .image_symbols()
                                .get_by_index(SymbolIndex::new(MACHO_SYMTAB_SELECTOR, index.0))?;
                            Some((address + offset, symbol.address().raw_offset()))
                        })
                    })
                    .expect("Mach-O fixture must contain an absolute relocation")
            }
        );

        let mut relocated = None;
        let mut contents = macho.image_contents();
        while let Some(contents) = contents.next()? {
            let Some(offset) = contents.offset_of(patch) else {
                continue;
            };
            relocated = contents.read_value::<u64>(offset);
            break;
        }

        assert_eq!(relocated, Some(target));
        Ok(())
    }

    #[test]
    fn aarch64_branch_relocation_is_applied() -> Result<(), LoaderError> {
        let macho = MachO::from_file(ARM64_OBJECT)?;
        let patch = with_macho!(
            macho.loaded_view(),
            file | {
                file.sections()
                    .find_map(|section| {
                        let address = macho_object_section_address(
                            file,
                            macho.base_address(),
                            section.index().0,
                        )?;
                        section
                            .relocations()
                            .find(|(_, relocation)| {
                                relocation.encoding() == RelocationEncoding::AArch64Call
                            })
                            .map(|(offset, _)| address + offset)
                    })
                    .expect("Mach-O fixture must contain an AArch64 call relocation")
            }
        );

        let mut relocated = None;
        let mut contents = macho.image_contents();
        while let Some(contents) = contents.next()? {
            let Some(offset) = contents.offset_of(patch) else {
                continue;
            };
            relocated = contents.read_value::<u32>(offset);
            break;
        }

        assert!(relocated.is_some_and(|instruction| instruction & 0x03ff_ffff != 0));
        Ok(())
    }

    #[test]
    fn relocation_extension_precedes_builtin() -> Result<(), LoaderError> {
        RELOCATION_EXTENSION_USED.store(false, Ordering::SeqCst);
        let macho = MachO::from_file_with(
            X86_64_OBJECT,
            attributes![ATTRIBUTE_IMAGE_BASE => 0x4000u64],
        )?;
        let mut found_marker = false;
        let mut contents = macho.image_contents();
        while let Some(contents) = contents.next()? {
            for offset in 0..contents.size().saturating_sub(7) {
                if contents.read_value::<u64>(offset) == Some(0x1234_5678_9abc_def0u64) {
                    found_marker = true;
                    break;
                }
            }
        }

        assert!(RELOCATION_EXTENSION_USED.load(Ordering::SeqCst));
        assert!(found_marker);
        Ok(())
    }

    #[test]
    fn loader_delegates_macho_metadata() -> Result<(), LoaderError> {
        let loader = Loader::from_file(UNIVERSAL_EXECUTABLE)?;

        assert!(matches!(loader, Loader::MachO(_)));
        assert_eq!(loader.platform().format(), Format::MachO);
        assert_eq!(loader.platform().os(), OperatingSystem::Macos);
        assert!(!loader.image_layout().banks().is_empty());

        Ok(())
    }
}
