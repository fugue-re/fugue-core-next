use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;
use std::path::Path;

use bitflags::bitflags;
use fallible_iterator::FallibleIterator;
use object::elf::{
    FileHeader32, FileHeader64, PF_R, PF_W, PF_X, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, STB_GLOBAL,
    STB_WEAK, STT_COMMON, STT_FUNC, STT_GNU_IFUNC, STT_LOOS, STT_NOTYPE, STT_OBJECT, STT_TLS,
};
use object::read::elf::{
    self, ElfFile, ElfSectionIterator, ElfSegment, ElfSegmentIterator, FileHeader,
};
use object::{
    Endianness, FileKind, Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, ReadRef,
    SectionFlags, SectionKind, SegmentFlags, SymbolFlags,
};
use range_set_blaze::{IntoRangesIter, RangeSetBlaze};

use crate::arch::Arch;
use crate::ir::traits::SymbolTableSelector;
use crate::ir::{
    Address, ExternSegment, IndexedSymbolTable, RawAddress, SegmentProperties, SymbolIndex,
    SymbolProperties,
};
use crate::lifter::ContextHint;
use crate::loader::object::object_language;
use crate::loader::{
    Loadable, LoadableAnalysers, LoadableFromBytes, LoadableFromFile, LoadableMetadata,
    LoadableSegment, LoadableSegmentBounds, LoaderError,
};
use crate::storage::ProjectStorageProvider;
use crate::storage::segments::space::AddressSpaceId;
use crate::types::attributes::{
    ATTRIBUTE_ADDRESS_SPACE, ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_IMAGE_BASE,
};
use crate::types::{AttributeMap, BytesOrMapping};

mod analysers;
pub use analysers::ElfAnalysers;

mod relocations;
pub use relocations::ElfSegmentRelocator;

const STT_GNU_UNIQUE: u8 = STT_LOOS;

pub const ELF_SYMTAB_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(0);
pub const ELF_DYNSYM_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(1);

pub const ATTRIBUTE_OVERRIDE_SEGMENT_PERMISSIONS: &str = "loader.elf.override_segment_permissions";
pub const ATTRIBUTE_SKIP_NOTE_SECTIONS: &str = "loader.elf.skip_note_sections";

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
}

pub struct Elf<'a> {
    object: ElfInner<'a>,
    architecture: Arch,
    metadata: LoadableMetadata,
    base: Address,
    preferred_base: u64,
    bounds: RangeInclusive<Address>,
    mapping_hints: BTreeMap<Address, ContextHint>,
    symbols: IndexedSymbolTable,
    sections: ElfSectionMap,
    extern_segm: ExternSegment,
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

        let view = object.borrow_view();
        let language = with_elf!(view, elf | object_language(elf))?;
        let architecture = Arch::new(language);

        let attributes = attributes.into();
        let target_space = attributes.get_attr::<AddressSpaceId>(ATTRIBUTE_ADDRESS_SPACE);

        let preferred_base = with_elf!(
            view,
            elf | elf
                .segments()
                .filter(|segm| segm.size() != 0)
                .map(|segm| segm.address())
                .min()
                .unwrap_or(0)
        );

        let base = attributes
            .get_attr::<RawAddress>(ATTRIBUTE_IMAGE_BASE)
            .map(|addr| Address::in_space(addr, target_space))
            .unwrap_or_else(|| Address::in_space(preferred_base, target_space));

        if base.offset() != preferred_base
            && with_elf!(view, elf | elf.kind()) == ObjectKind::Executable
        {
            return Err(LoaderError::format_with(
                "cannot rebase a non-relocatable ELF executable",
            ));
        }

        let config = ElfLoaderProperties::new(&attributes);

        let ElfSymbolData {
            bounds,
            symbols,
            sections,
            mapping_hints,
            extern_segm,
        } = with_elf!(
            view,
            elf | ElfSymbolData::from_elf(elf, &architecture, base, preferred_base, config)?
        );

        let metadata = LoadableMetadata::new(
            object.borrow_data(),
            format!("Fugue v{} ELF Loader", env!("CARGO_PKG_VERSION")),
        );

        let mut slf = Self {
            object,
            architecture,
            metadata,
            base,
            preferred_base,
            bounds,
            mapping_hints,
            symbols,
            sections,
            extern_segm,
            attributes,
        };

        if let Some(entry) = slf.entry() {
            slf.attributes.set_attr(ATTRIBUTE_ENTRY_POINT, entry);
        }

        Ok(slf)
    }

    pub fn entry(&self) -> Option<Address> {
        let addr = with_elf!(self.object.borrow_view(), elf | elf.entry());
        (addr != 0).then_some(Address::new(
            self.base.space(),
            addr.wrapping_sub(self.preferred_base)
                .wrapping_add(self.base.offset()),
        ))
    }

    pub fn convention(&self) -> Option<&'a str> {
        None
    }

    pub fn loaded_view(&self) -> &ElfFileRepr<'_, 'a> {
        self.object.borrow_view()
    }

    pub fn mapping_hints(&self) -> &BTreeMap<Address, ContextHint> {
        &self.mapping_hints
    }

    pub fn symbols(&self) -> &IndexedSymbolTable {
        &self.symbols
    }

    pub fn extern_segment(&self) -> &ExternSegment {
        &self.extern_segm
    }

    pub fn is_object(&self) -> bool {
        with_elf!(
            self.object.borrow_view(),
            elf | elf.kind() == ObjectKind::Relocatable
        )
    }

    pub fn base_address(&self) -> Address {
        self.base
    }

    pub fn target_space(&self) -> AddressSpaceId {
        self.base.space()
    }
}

#[derive(Debug, Default)]
pub(crate) struct ElfSectionMap(Vec<Option<Address>>);

impl ElfSectionMap {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, index: usize, address: Address) {
        if index >= self.0.len() {
            self.0.resize(index + 1, None);
        }
        self.0[index] = Some(address);
    }

    pub(crate) fn get(&self, index: usize) -> Option<Address> {
        self.0.get(index).copied().flatten()
    }
}

struct ElfSymbolData {
    bounds: RangeInclusive<Address>,
    mapping_hints: BTreeMap<Address, ContextHint>,
    symbols: IndexedSymbolTable,
    sections: ElfSectionMap,
    extern_segm: ExternSegment,
}

impl ElfSymbolData {
    fn from_elf<'a>(
        elf: &'a impl Object<'a>,
        arch: &Arch,
        base_addr: Address,
        preferred_base: u64,
        config: ElfLoaderProperties,
    ) -> Result<Self, LoaderError> {
        let target_space = base_addr.space();
        // TODO:
        // - base address should be configurable.
        // - determine if GNU and hence IFUNC and UNIQUE are supported.

        let is_object = elf.kind() == ObjectKind::Relocatable;
        let addr_size = arch.language().address_size();

        // NOTE: this is to force a larger alignment on ARM, since the sinc uses 2 byte alignment,
        // which is only applicable for Thumb.
        let addr_align = arch.language().address_alignment().max(addr_size);

        let mut sections = ElfSectionMap::new();
        let mut mapping_hints = BTreeMap::new();

        let mut min_addr = base_addr;
        let mut max_addr = base_addr;

        let extern_base = if is_object {
            let mut base = base_addr.offset();
            for sect in elf.sections() {
                let SectionFlags::Elf { sh_flags } = sect.flags() else {
                    continue;
                };

                if (sh_flags as u32 & SHF_ALLOC) != SHF_ALLOC {
                    continue;
                }

                if config.skip_note_sections() && sect.kind() == SectionKind::Note {
                    continue;
                }

                let align = sect.align().max(1);
                let aligned_start = base.wrapping_add(align.wrapping_sub(1)) & !align.wrapping_sub(1);

                if aligned_start < base {
                    tracing::debug!("section start {aligned_start:#x} overflow; skipping section");
                    continue;
                }

                sections.insert(sect.index().0, Address::in_space(aligned_start, target_space));

                base = aligned_start
                    .checked_add(sect.size().max(1))
                    .ok_or_else(|| LoaderError::address_overflow(base_addr))?;
            }

            max_addr = Address::in_space(base, target_space);
            base
        } else {
            for (addr, size) in elf
                .sections()
                .map(|sect| (sect.address(), sect.size()))
                .chain(elf.segments().map(|segm| (segm.address(), segm.size())))
                .filter(|(addr, size)| *size != 0 && *addr >= preferred_base)
            {
                let curr_min = base_addr
                    .checked_add(addr - preferred_base)
                    .ok_or_else(|| LoaderError::address_overflow(base_addr))?;

                let curr_max = curr_min
                    .checked_add(size)
                    .ok_or_else(|| LoaderError::address_overflow(base_addr))?;

                max_addr = max_addr.max(curr_max);
                min_addr = min_addr.min(curr_min);
            }
            max_addr
                .offset()
                .checked_add(addr_size as u64)
                .ok_or_else(|| LoaderError::address_overflow(base_addr))?
        };

        let aligned_extern_base = extern_base.wrapping_add(addr_align.wrapping_sub(1) as u64)
            & !(addr_align as u64).wrapping_sub(1);

        if aligned_extern_base < extern_base {
            return Err(LoaderError::address_overflow(base_addr));
        }

        let mut symbols = IndexedSymbolTable::new();

        for (section, symbol) in elf
            .symbols()
            .filter_map(|sym| sym.section_index().map(|idx| (idx, sym)))
        {
            let address = if is_object {
                let Some(section_start) = sections.get(section.0) else {
                    continue;
                };
                Address::new(
                    target_space,
                    symbol.address().wrapping_add(section_start.offset()),
                )
            } else {
                Address::new(
                    target_space,
                    symbol
                        .address()
                        .wrapping_sub(preferred_base)
                        .wrapping_add(base_addr.offset()),
                )
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
                tracing::debug!("symbol {address} is not a function or data: {st_bind:x}/{st_type:x}");
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
                address,
                symbol.name().ok().unwrap_or_default(),
                properties,
            );
        }

        let syms = if is_object {
            elf.symbols()
        } else {
            elf.dynamic_symbols()
        };

        // NOTE: this template is used to create a stub for the external symbols, such that
        // if we were to consider the external address as a function, and call to it, we would
        // hit valid code, and return.

        let mut extern_segm = ExternSegment::new(
            Address::new(target_space, aligned_extern_base),
            addr_align,
            arch.external_thunk_template(),
        );

        // TODO: refactor the inner logic so we avoid duplication between the two loops.

        for (index, sym, kind) in syms.enumerate().filter_map(|(index, sym)| {
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
            let addr = if kind.is_extern() {
                extern_segm
                    .add_extern()
                    .ok_or_else(|| LoaderError::address_overflow(base_addr))?
            } else if is_object {
                let Some(section_start) = sym
                    .section_index()
                    .and_then(|section| sections.get(section.0))
                else {
                    continue;
                };
                Address::new(
                    target_space,
                    sym.address().wrapping_add(section_start.offset()),
                )
            } else {
                Address::new(
                    target_space,
                    sym.address()
                        .wrapping_sub(preferred_base)
                        .wrapping_add(base_addr.offset()),
                )
            };
            let sym = sym.name().ok();

            symbols.insert(
                SymbolIndex::new(ELF_DYNSYM_SELECTOR, index),
                addr,
                sym.unwrap_or_default(),
                kind,
            );
        }

        let max_addr = extern_segm
            .last_address()
            .unwrap_or(Address::new(target_space, max_addr));
        let bounds = Address::new(target_space, min_addr)..=max_addr;

        Ok(Self {
            bounds,
            mapping_hints,
            symbols,
            sections,
            extern_segm,
        })
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

        config
    }

    pub(crate) fn is_object(&self) -> bool {
        self.contains(Self::IS_OBJECT)
    }

    pub(crate) fn skip_note_sections(&self) -> bool {
        self.contains(Self::SKIP_NOTE_SECTIONS)
    }

    pub(crate) fn ignore_segment_exec_permission(&self) -> bool {
        self.contains(Self::IGNORE_SEGMENT_EXEC_PERMISSION)
    }
}

pub(crate) struct ElfLoadableSegments<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    // reference to the ELF
    pub(crate) elf: &'file ElfFile<'data, Elf, R>,
    // segments iterator
    pub(crate) segms: ElfSegmentIterator<'data, 'file, Elf, R>,
    // sections iterator
    pub(crate) sects: ElfSectionIterator<'data, 'file, Elf, R>,
    // ranges already covered
    covered: RangeSetBlaze<u64>,
    // split segments that span multiple unmapped ranges
    segms_split: Option<(IntoRangesIter<u64>, ElfSegment<'data, 'file, Elf, R>)>,
    // current base address
    pub(crate) current_base: Address,
    // the binary's preferred load address
    pub(crate) preferred_base: u64,
    // mapping hints provided by mapping symbols
    pub(crate) mapping_hints: &'file BTreeMap<Address, ContextHint>,
    // mapping of local and external symbols
    pub(crate) symbols: &'file IndexedSymbolTable,
    // assigned base address per section index (relocatable objects)
    pub(crate) sections: &'file ElfSectionMap,
    // virtual segment containing externals
    pub(crate) extern_segm: Option<&'file ExternSegment>,
    // loader config
    config: ElfLoaderProperties,
}

impl<'data, 'file, Elf, R> ElfLoadableSegments<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn new(
        elf: &'file ElfFile<'data, Elf, R>,
        mapping_hints: &'file BTreeMap<Address, ContextHint>,
        symbols: &'file IndexedSymbolTable,
        sections: &'file ElfSectionMap,
        externs: &'file ExternSegment,
        base: Address,
        preferred_base: u64,
        mut config: ElfLoaderProperties,
    ) -> Self {
        if elf.kind() == ObjectKind::Relocatable {
            config.insert(ElfLoaderProperties::IS_OBJECT);
        }
        Self {
            elf,
            sects: elf.sections(),
            segms: elf.segments(),
            covered: RangeSetBlaze::new(),
            segms_split: None,
            current_base: base,
            preferred_base,
            mapping_hints,
            symbols,
            sections,
            extern_segm: Some(externs),
            config,
        }
    }

    pub(crate) fn extern_segment(&mut self) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
        let Some(externs) = self.extern_segm.take().filter(|e| !e.is_empty()) else {
            return Ok(None);
        };
        let extern_size = externs.size();
        let extern_padding = externs.aligned_template_size() - externs.template().len();

        let address = externs.address();
        let last_address = externs.last_address().expect("not empty");

        let mut bytes = Vec::with_capacity(extern_size);

        let function_hints = self
            .symbols
            .iter()
            .filter_map(|(_, sym)| {
                if sym
                    .properties()
                    .contains(SymbolProperties::FUNCTION | SymbolProperties::EXTERN)
                {
                    Some(sym.address())
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();

        for addr in externs.iter() {
            if function_hints.contains(&addr) {
                bytes.extend_from_slice(externs.template().bytes());
                bytes.resize(bytes.len() + extern_padding, 0);
            } else {
                bytes.resize(bytes.len() + externs.aligned_template_size(), 0);
            }
        }

        self.covered
            .ranges_insert(address.offset()..=last_address.offset());

        let lsegm = LoadableSegment {
            name: Cow::Borrowed("EXTERN"),
            address: externs.address(),
            properties: SegmentProperties::EXTERNAL
                | SegmentProperties::PERM_READ
                | SegmentProperties::PERM_EXECUTE,
            bytes: Cow::Owned(bytes),
            mapping_hints: Cow::Owned(BTreeMap::new()),
            function_hints: Cow::Owned(function_hints),
        };

        Ok(Some(lsegm))
    }

    pub(crate) fn next_unlinked(&mut self) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
        for sect in self.sects.by_ref() {
            let Some(address) = self.sections.get(sect.index().0) else {
                continue;
            };

            let span = sect.size().max(1);
            let last_address = address
                .checked_add(span.wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(address))?;

            if last_address < address {
                tracing::debug!("section bounds {address}-{last_address} overflow; skipping");
                continue;
            }

            tracing::trace!("processing section {address}-{last_address}");

            let data = sect.data().unwrap_or_default();

            let vrange = address.offset()..=last_address.offset();
            if !self
                .covered
                .is_disjoint(&RangeSetBlaze::from_iter([vrange.clone()]))
            {
                tracing::debug!("overlapping section {address}-{last_address}; skipping");
                continue;
            }

            tracing::trace!("loading section {address}-{last_address}");

            let bytes = if data.len() as u64 != span {
                let mut data = data.to_owned();
                data.resize(span as _, 0);

                Cow::Owned(data)
            } else {
                Cow::Borrowed(data)
            };

            let mut lsegm = LoadableSegment {
                name: sect
                    .name()
                    .ok()
                    .map_or_else(|| Cow::Borrowed("LOAD"), Cow::Borrowed),
                address,
                properties: elf_section_properties(&sect, &self.config),
                bytes,
                mapping_hints: Cow::Owned(
                    self.mapping_hints
                        .range(address..=last_address)
                        .map(|(k, v)| (*k, v.clone()))
                        .collect(),
                ),
                ..Default::default()
            };

            self.covered.ranges_insert(vrange);

            let relocator =
                ElfSegmentRelocator::new(self.elf, self.symbols, self.config.is_object(), address);

            relocator.apply(address, &mut lsegm, &sect)?;

            return Ok(Some(lsegm));
        }

        self.extern_segment()
    }

    pub(crate) fn next_linked_split(
        &mut self,
    ) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
        let Some((covered, segm)) = self.segms_split.as_mut() else {
            return Ok(None);
        };

        let relocator = ElfSegmentRelocator::new(
            self.elf,
            self.symbols,
            self.config.is_object(),
            Address::new(
                self.current_base.space(),
                self.current_base.offset().wrapping_sub(self.preferred_base),
            ),
        );

        if let Some(range) = covered.next() {
            let data = segm.data().unwrap_or_default();

            let loaded_segm_start = segm
                .address()
                .wrapping_sub(self.preferred_base)
                .wrapping_add(self.current_base.offset());
            let rvsize = (*range.end() - *range.start() + 1) as usize;
            let rvstart = (*range.start() - loaded_segm_start) as usize;
            let rvend = rvsize + rvstart;

            let bytes = if data.len() < rvend {
                let mut bytes = Vec::with_capacity(rvsize);

                if rvstart < data.len() {
                    bytes.extend_from_slice(&data[rvstart..]);
                }

                bytes.resize(rvsize, 0u8);

                Cow::Owned(bytes)
            } else {
                Cow::Borrowed(&data[rvstart..rvend])
            };

            let address = Address::new(self.current_base.space(), *range.start());
            let last_address = address
                .checked_add((bytes.len() as u64).wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(address))?;

            tracing::trace!("loading segment {address}-{last_address}");

            let mut lsegm = LoadableSegment {
                name: segm
                    .name()
                    .ok()
                    .flatten()
                    .map_or_else(|| Cow::Borrowed("LOAD"), |name| Cow::Owned(name.to_owned())),
                address,
                properties: elf_segment_properties(&*segm, &self.config),
                bytes,
                mapping_hints: Cow::Owned(
                    self.mapping_hints
                        .range(address..=last_address)
                        .map(|(k, v)| (*k, v.clone()))
                        .collect(),
                ),
                ..Default::default()
            };

            self.covered.ranges_insert(range);

            relocator.apply_dynamic_relocations(address, &mut lsegm)?;

            return Ok(Some(lsegm));
        }

        self.segms_split = None;

        Ok(None)
    }

    pub(crate) fn next_linked_section(
        &mut self,
    ) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
        let relocator = ElfSegmentRelocator::new(
            self.elf,
            self.symbols,
            self.config.is_object(),
            Address::new(
                self.current_base.space(),
                self.current_base.offset().wrapping_sub(self.preferred_base),
            ),
        );

        for sect in self.sects.by_ref() {
            let SectionFlags::Elf { sh_flags } = sect.flags() else {
                continue;
            };

            let size = sect.size();

            if size == 0 || (sh_flags as u32 & SHF_ALLOC) != SHF_ALLOC {
                continue;
            }

            let address = Address::new(
                self.current_base.space(),
                sect.address()
                    .wrapping_sub(self.preferred_base)
                    .wrapping_add(self.current_base.offset()),
            );

            let last_address = address
                .checked_add(size.wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(address))?;

            if last_address < address {
                tracing::debug!("section bounds {address}-{last_address} overflow; skipping");
                continue;
            }

            tracing::trace!("processing section {address}-{last_address}");

            let data = sect.data().unwrap_or_default();

            let vrange = address.offset()..=last_address.offset();
            if !self
                .covered
                .is_disjoint(&RangeSetBlaze::from_iter([vrange.clone()]))
            {
                tracing::debug!("overlapping section {address}-{last_address}; skipping");
                continue;
            }

            tracing::trace!("loading section {address}-{last_address}");

            let bytes = if data.len() as u64 != sect.size() {
                let mut data = data.to_owned();
                data.resize(sect.size() as _, 0);

                Cow::Owned(data)
            } else {
                Cow::Borrowed(data)
            };

            let mut lsegm = LoadableSegment {
                name: sect
                    .name()
                    .ok()
                    .map_or_else(|| Cow::Borrowed("LOAD"), Cow::Borrowed),
                address,
                properties: elf_section_properties(&sect, &self.config),
                bytes,
                mapping_hints: Cow::Owned(
                    self.mapping_hints
                        .range(address..=last_address)
                        .map(|(k, v)| (*k, v.clone()))
                        .collect(),
                ),
                ..Default::default()
            };

            self.covered.ranges_insert(vrange);

            relocator.apply(address, &mut lsegm, &sect)?;

            return Ok(Some(lsegm));
        }

        Ok(None)
    }

    pub(crate) fn next_linked_segment(
        &mut self,
    ) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
        let relocator = ElfSegmentRelocator::new(
            self.elf,
            self.symbols,
            self.config.is_object(),
            Address::new(
                self.current_base.space(),
                self.current_base.offset().wrapping_sub(self.preferred_base),
            ),
        );

        for segm in self.segms.by_ref() {
            let size = segm.size();

            if segm.size() == 0 {
                continue;
            }

            let space = self.current_base.space();
            let address = Address::new(
                space,
                segm.address()
                    .wrapping_sub(self.preferred_base)
                    .wrapping_add(self.current_base.offset()),
            );

            let last_address = address
                .checked_add(size.wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(address))?;

            if last_address < address {
                tracing::debug!("segment bounds {address}-{last_address} overflow; skipping");
                continue;
            }

            tracing::trace!("processing segment {address}-{last_address}");

            let data = segm.data().unwrap_or_default();

            let vrange = address.offset()..=last_address.offset();

            let covered = RangeSetBlaze::from_iter([vrange.clone()]) - &self.covered;

            if covered.is_empty() {
                tracing::trace!("segment range {address}-{last_address} already covered");
                continue;
            }

            let should_split = covered.ranges_len() > 1;

            if should_split {
                tracing::trace!(
                    "segment range {address}-{last_address} spans multiple unmapped ranges; splitting"
                );
            }

            let mut ranges = covered.into_ranges();
            let range = ranges.next().expect("not empty");

            let rvsize = (*range.end() - *range.start() + 1) as usize;
            let rvstart = (*range.start() - *vrange.start()) as usize;
            let rvend = rvsize + rvstart;

            let bytes = if data.len() < rvend {
                let mut bytes = Vec::with_capacity(rvsize);

                if rvstart < data.len() {
                    bytes.extend_from_slice(&data[rvstart..]);
                }

                bytes.resize(rvsize, 0u8);

                Cow::Owned(bytes)
            } else {
                Cow::Borrowed(&data[rvstart..rvend])
            };

            let address = Address::new(space, *range.start());
            let last_address = address
                .checked_add((bytes.len() as u64).wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(address))?;

            tracing::trace!("loading segment {address}-{last_address}");

            let mut lsegm = LoadableSegment {
                name: segm
                    .name()
                    .ok()
                    .flatten()
                    .map_or_else(|| Cow::Borrowed("LOAD"), |name| Cow::Owned(name.to_owned())),
                address,
                properties: elf_segment_properties(&segm, &self.config),
                bytes,
                mapping_hints: Cow::Owned(
                    self.mapping_hints
                        .range(address..=last_address)
                        .map(|(k, v)| (*k, v.clone()))
                        .collect(),
                ),
                ..Default::default()
            };

            if should_split {
                self.segms_split = Some((ranges, segm));
            }

            self.covered.ranges_insert(range);

            relocator.apply_dynamic_relocations(address, &mut lsegm)?;

            return Ok(Some(lsegm));
        }

        Ok(None)
    }

    pub(crate) fn next_linked(&mut self) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
        if let Some(v) = self.next_linked_split()? {
            return Ok(Some(v));
        }

        if let Some(v) = self.next_linked_section()? {
            self.config.insert(ElfLoaderProperties::HAS_LOADED_SECTIONS);
            return Ok(Some(v));
        }

        if let Some(v) = self.next_linked_segment()? {
            return Ok(Some(v));
        }

        self.extern_segment()
    }
}

impl<'data, 'file, Elf, R> FallibleIterator for ElfLoadableSegments<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    type Error = LoaderError;
    type Item = LoadableSegment<'data>;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.config.is_object() {
            self.next_unlinked()
        } else {
            self.next_linked()
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let sects_bound = self.sects.size_hint().0;
        let segms_bound = self.segms.size_hint().0;
        let splits = self
            .segms_split
            .as_ref()
            .map(|(it, _)| it.size_hint().0)
            .unwrap_or(0);
        (sects_bound + segms_bound + splits, None)
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

        loaded.metadata.set_path(path.display().to_string());

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
        &self.metadata
    }

    fn architecture(&self) -> Arch {
        self.architecture.clone()
    }

    fn symbols(&self) -> Option<&IndexedSymbolTable> {
        Some(&self.symbols)
    }

    fn segments<'b>(
        &'b self,
    ) -> impl FallibleIterator<Item = LoadableSegment<'b>, Error = LoaderError> + 'b {
        let view = self.object.borrow_view();
        let props = ElfLoaderProperties::new(self.attributes());

        with_elf!(
            view,
            elf | Box::new(ElfLoadableSegments::new(
                elf,
                &self.mapping_hints,
                &self.symbols,
                &self.sections,
                &self.extern_segm,
                self.base,
                self.preferred_base,
                props,
            ))
                as Box<dyn FallibleIterator<Item = LoadableSegment, Error = LoaderError>>
        )
    }

    fn segment_bounds(&self) -> LoadableSegmentBounds {
        let start = *self.bounds.start();
        let end = *self.bounds.end() + 1usize;
        LoadableSegmentBounds::new(start..end)
    }

    fn analysers<P>(&self) -> impl LoadableAnalysers<P>
    where
        P: ProjectStorageProvider,
    {
        ElfAnalysers::new(self)
    }
}

#[cfg(test)]
mod test {
    use fallible_iterator::FallibleIterator;
    use object::elf::{R_ARM_JUMP_SLOT, R_ARM_RELATIVE};
    use object::{Object, RelocationFlags, RelocationTarget};

    use super::{ELF_DYNSYM_SELECTOR, Elf, ElfFileRepr};
    use crate::ir::{Address, RawAddress, SymbolIndex};
    use crate::loader::Loadable;
    use crate::types::BytesOrMapping;
    use crate::types::attributes::{ATTRIBUTE_IMAGE_BASE, AttributeMap};

    #[test]
    fn test_elf_exe() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let elf = Elf::new(BytesOrMapping::from_file("tests/ls.elf")?)?;
            let mut segments = elf.segments();
            while let Some(segm) = segments.next()? {
                tracing::info!(
                    "{}-{} ({:?})",
                    segm.address(),
                    segm.last_address(),
                    segm.name()
                );
            }
            tracing::info!("architecture: {}", elf.architecture());

            for (_, sym) in elf.symbols().iter() {
                tracing::info!("symbol {sym}");
            }

            Ok(())
        })
    }

    #[test]
    fn test_elf_dyn() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let elf = Elf::new(BytesOrMapping::from_file("tests/libipmi.so")?)?;
            let mut segments = elf.segments();
            while let Some(segm) = segments.next()? {
                tracing::info!(
                    "{}-{} ({:?})",
                    segm.address(),
                    segm.address() + segm.len(),
                    segm.name()
                );
            }
            tracing::info!("architecture: {}", elf.architecture());

            for (_, sym) in elf.symbols().iter() {
                tracing::info!("symbol {sym}");
            }

            for (addr, hint) in elf.mapping_hints() {
                tracing::info!("mapping hint {addr}: {hint}");
            }

            Ok(())
        })
    }

    #[test]
    fn test_elf_rel() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let elf = Elf::new(BytesOrMapping::from_file("tests/liblzma_la-crc64-fast.o")?)?;
            let mut segments = elf.segments();
            while let Some(segm) = segments.next()? {
                tracing::info!(
                    "{}-{} ({:?})",
                    segm.address(),
                    segm.address() + segm.len(),
                    segm.name()
                );
            }
            tracing::info!("architecture: {}", elf.architecture());

            for (_, sym) in elf.symbols().iter() {
                tracing::info!("symbol {sym}");
            }

            Ok(())
        })
    }

    #[test]
    fn test_elf_ko_rel() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let elf = Elf::new(BytesOrMapping::from_file("tests/inv-icm42600.ko")?)?;
            let mut segments = elf.segments();
            while let Some(segm) = segments.next()? {
                tracing::info!(
                    "{}-{} ({:?})",
                    segm.address(),
                    segm.address() + segm.len(),
                    segm.name()
                );
            }
            tracing::info!("architecture: {}", elf.architecture());

            for (_, sym) in elf.symbols().iter() {
                tracing::info!("symbol {sym}");
            }

            Ok(())
        })
    }

    #[test]
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
        let mut segments = elf.segments();

        while let Some(segm) = segments.next()? {
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
        let mut segments = elf.segments();

        while let Some(segm) = segments.next()? {
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

                    elf.symbols()
                        .get_by_index(SymbolIndex::new(ELF_DYNSYM_SELECTOR, index.0))
                        .map(|(_, entry)| (offset, entry.address().offset()))
                })
            })()
        )
        .expect("R_ARM_JUMP_SLOT relocation");

        let relocation_address = elf
            .base_address()
            .checked_add(relocation_offset)
            .expect("ARM jump slot address");

        let mut relocated_value = None;
        let mut segments = elf.segments();

        while let Some(segm) = segments.next()? {
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
}
