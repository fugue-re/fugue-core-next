use std::borrow::Cow;
use std::collections::BTreeSet;
use std::ops::RangeInclusive;
use std::path::Path;

use fallible_iterator::FallibleIterator;

use object::elf::{
    FileHeader32, FileHeader64, PF_R, PF_W, PF_X, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, STB_GLOBAL,
    STB_WEAK, STT_COMMON, STT_FUNC, STT_GNU_IFUNC, STT_NOTYPE, STT_OBJECT, STT_TLS,
};
use object::read::elf::{
    self, ElfFile, ElfSectionIterator, ElfSegment, ElfSegmentIterator, FileHeader,
};
use object::{
    Endianness, FileKind, Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, ReadRef,
    SectionFlags, SegmentFlags, SymbolFlags,
};

use range_set_blaze::{IntoRangesIter, RangeSetBlaze};

use crate::arch::Arch;
use crate::ir::{
    Address, ExternSegment, IndexedSymbolTable, SegmentProperties, SymbolIndex, SymbolProperties,
};
use crate::loader::object::object_language;
use crate::loader::{
    Loadable, LoadableFromBytes, LoadableFromFile, LoadableMetadata, LoadableSegment, LoaderError,
};
use crate::types::{AttributeMap, BytesOrMapping};

mod relocations;
pub use relocations::ElfSegmentRelocator;

pub const ELF_SYMTAB_SELECTOR: usize = 0;
pub const ELF_DYNSYM_SELECTOR: usize = 1;

#[ouroboros::self_referencing]
struct ElfInner<'a> {
    data: BytesOrMapping<'a>,
    #[borrows(data)]
    #[covariant]
    view: ElfFileRepr<'this, 'a>,
}

enum ElfFileRepr<'this, 'data> {
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
    bounds: RangeInclusive<Address>,
    symbols: IndexedSymbolTable,
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

        let (bounds, symbols, extern_segm) = with_elf!(view, elf | elf_symbols(elf, &architecture));

        let metadata = LoadableMetadata::new(
            object.borrow_data(),
            format!("Fugue v{} ELF Loader", env!("CARGO_PKG_VERSION")),
        );

        Ok(Self {
            object,
            architecture,
            metadata,
            bounds,
            symbols,
            extern_segm,
            attributes: attributes.into(),
        })
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
}

// TODO: this will return a ExternSegment
pub fn elf_symbols<'a>(
    elf: &'a impl Object<'a>,
    arch: &Arch,
) -> (RangeInclusive<Address>, IndexedSymbolTable, ExternSegment) {
    // TODO:
    // - base address should be configurable.

    let is_object = elf.kind() == ObjectKind::Relocatable;
    let addr_size = arch.language().address_size();

    // NOTE: this is to force a larger alignment on ARM, since the sinc uses 2 byte alignment,
    // which is only applicable for Thumb.
    let addr_align = arch.language().address_alignment().max(addr_size);

    let mut section_map = Vec::new();

    let base_addr = Address::zero();

    let mut min_addr = base_addr;
    let mut max_addr = base_addr;

    let base = if is_object {
        let mut base = base_addr.offset();
        for sect in elf.sections() {
            let SectionFlags::Elf { sh_flags } = sect.flags() else {
                // NOTE: we could probably panic here
                section_map.push(None);
                continue;
            };

            if (sh_flags as u32 & SHF_ALLOC) != SHF_ALLOC {
                section_map.push(None);
                continue;
            }

            if sect.size() == 0 {
                section_map.push(None);
                base += 1; // assume byte alignment (same as IDA Pro)
                continue;
            }

            let aligned_start =
                (base + sect.align().wrapping_sub(1)) & !sect.align().wrapping_sub(1);

            section_map.push(Some(aligned_start));

            base = aligned_start + sect.size();
        }

        max_addr = Address::from(base);
        base
    } else {
        for (addr, size) in elf
            .sections()
            .map(|sect| (sect.address(), sect.size()))
            .chain(elf.segments().map(|segm| (segm.address(), segm.size())))
            .filter(|(_, size)| *size != 0)
        {
            max_addr = max_addr.max(Address::from(addr + size));
            min_addr = min_addr.min(Address::from(addr));
        }
        max_addr.offset() + addr_size as u64
    };

    let aligned_base =
        (base + addr_align.wrapping_sub(1) as u64) & !(addr_align as u64).wrapping_sub(1);

    let mut symbols = IndexedSymbolTable::new();

    for (section, symbol) in elf
        .symbols()
        .filter_map(|sym| sym.section_index().map(|idx| (idx, sym)))
    {
        let Some(section_start) = section_map
            .get(section.0)
            .and_then(|start| *start)
            .or_else(|| Some(elf.section_by_index(section).ok()?.address()))
        else {
            continue;
        };

        let address = section_start + symbol.address();

        tracing::trace!(
            "symbol {} in section {section:?} at {address:#x}",
            symbol.name().ok().unwrap_or("<unnamed>"),
        );

        let SymbolFlags::Elf { st_info, .. } = symbol.flags() else {
            continue;
        };

        let st_type = st_info & 0x0f;

        symbols.insert(
            SymbolIndex::new(ELF_SYMTAB_SELECTOR, symbol.index().0),
            address,
            symbol.name().ok().unwrap_or_default(),
            if [STT_FUNC, STT_GNU_IFUNC].contains(&st_type) {
                SymbolProperties::FUNCTION
            } else if [STT_COMMON, STT_OBJECT /*, STT_TLS */].contains(&st_type) {
                SymbolProperties::DATA
            } else {
                tracing::debug!("symbol {address:#x} is not a function or data: {st_type:x}");
                SymbolProperties::NONE
            },
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

    // FIXME: this is incorrect for shared objects, where we have exports. The dynamic symbol
    // table will contain both imports and exports, and by our conventions, we should only add
    // imports to the externs table, which we do, but we therefore miss the exports. Unfortunately,
    // the way object exposes the symbol tables, each has its own set of symbol indices...

    let mut externs = ExternSegment::new(aligned_base, addr_align, arch.external_thunk_template());

    for (index, sym, kind) in syms.enumerate().filter_map(|(index, sym)| {
        let SymbolFlags::Elf { st_info, .. } = sym.flags() else {
            return None;
        };

        let st_bind = st_info >> 4;
        let st_type = st_info & 0x0f;

        let is_import = (st_bind == STB_GLOBAL || st_bind == STB_WEAK) && sym.address() == 0;

        if (is_import && !is_object) || (is_object && is_import && st_type == STT_NOTYPE) {
            let kind = if [STT_FUNC, STT_GNU_IFUNC].contains(&st_type) {
                SymbolProperties::FUNCTION
            } else if [STT_COMMON, STT_OBJECT, STT_TLS].contains(&st_type) {
                SymbolProperties::DATA
            } else {
                SymbolProperties::NONE
            };

            Some((index, sym, kind))
        } else {
            tracing::debug!(
                "skipping symbol {} (bind: {st_bind}, type: {st_type}, addr: {:#x})",
                sym.name().ok().unwrap_or("<unnamed>"),
                sym.address(),
            );
            None
        }
    }) {
        let sym = sym.name().ok();
        let addr = externs.add_extern();

        symbols.insert(
            SymbolIndex::new(ELF_DYNSYM_SELECTOR, index),
            addr,
            sym.unwrap_or_default(),
            kind,
        );
    }

    let max_addr = externs.last_address().unwrap_or(max_addr);
    let bounds = min_addr..=max_addr;

    (bounds, symbols, externs)
}

pub fn elf_section_properties<'a>(sect: &impl ObjectSection<'a>) -> SegmentProperties {
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

pub fn elf_segment_properties<'a>(segm: &impl ObjectSegment<'a>) -> SegmentProperties {
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

    if p_flags & PF_X == PF_X {
        props.insert(SegmentProperties::PERM_EXECUTE);
    }

    if segm.file_range().1 == 0 {
        props.insert(SegmentProperties::UNINITIALISED);
    }

    props
}

pub fn elf_section<'a>(sect: &impl ObjectSection<'a>) -> Option<LoadableSegment<'a>> {
    let SectionFlags::Elf { sh_flags } = sect.flags() else {
        return None;
    };

    if sect.size() == 0 || (sh_flags as u32 & SHF_ALLOC) != SHF_ALLOC {
        return None;
    }

    let address = Address::from(sect.address());
    let data = sect.data().unwrap_or_default();

    let bytes = if data.len() as u64 != sect.size() {
        let mut data = data.to_owned();
        data.resize(sect.size() as _, 0);

        Cow::Owned(data)
    } else {
        Cow::Borrowed(data)
    };

    Some(LoadableSegment {
        name: sect
            .name()
            .ok()
            .map_or_else(|| Cow::Borrowed("LOAD"), |name| Cow::Borrowed(name)),
        address,
        properties: elf_section_properties(sect),
        bytes,
        ..Default::default()
    })
}

pub fn elf_segment<'a>(segm: &impl ObjectSegment<'a>) -> Option<LoadableSegment<'a>> {
    if segm.size() == 0 {
        return None;
    }

    let address = Address::from(segm.address());
    let data = segm.data().unwrap_or_default();

    let bytes = if data.len() as u64 != segm.size() {
        let mut data = data.to_owned();
        data.resize(segm.size() as _, 0);

        Cow::Owned(data)
    } else {
        Cow::Borrowed(data)
    };

    Some(LoadableSegment {
        name: segm
            .name()
            .ok()
            .flatten()
            .map_or_else(|| Cow::Borrowed("LOAD"), |name| Cow::Owned(name.to_owned())),
        address,
        properties: elf_segment_properties(segm),
        bytes,
        ..Default::default()
    })
}

pub fn elf_sections<'a>(
    elf: &'a impl Object<'a>,
) -> impl Iterator<Item = LoadableSegment<'a>> + 'a {
    elf.sections()
        .into_iter()
        .filter_map(|sect| elf_section(&sect))
}

pub fn elf_segments<'a>(
    elf: &'a impl Object<'a>,
) -> impl Iterator<Item = LoadableSegment<'a>> + 'a {
    elf.segments()
        .into_iter()
        .filter_map(|segm| elf_segment(&segm))
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
    // mapping of local and external symbols
    pub(crate) symbols: &'file IndexedSymbolTable,
    // virtual segment containing externals
    pub(crate) extern_segm: Option<&'file ExternSegment>,
    // if we're working with an object file or not
    is_object: bool,
}

impl<'data, 'file, Elf, R> ElfLoadableSegments<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn new(
        elf: &'file ElfFile<'data, Elf, R>,
        symbols: &'file IndexedSymbolTable,
        externs: &'file ExternSegment,
    ) -> Self {
        let is_object = elf.kind() == ObjectKind::Relocatable;
        Self {
            elf,
            sects: elf.sections(),
            segms: elf.segments(),
            covered: RangeSetBlaze::new(),
            segms_split: None,
            current_base: Address::zero(),
            symbols,
            extern_segm: Some(externs),
            is_object,
        }
    }

    pub(crate) fn extern_segment(&mut self) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
        let Some(externs) = self.extern_segm.take().filter(|e| !e.is_empty()) else {
            return Ok(None);
        };
        let extern_size = externs.size() as usize;
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
            function_hints: Cow::Owned(function_hints),
        };

        Ok(Some(lsegm))
    }

    pub(crate) fn next_unlinked(&mut self) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
        let relocator = ElfSegmentRelocator::new(self.elf, self.symbols, self.is_object);

        while let Some(sect) = self.sects.next() {
            let SectionFlags::Elf { sh_flags } = sect.flags() else {
                continue;
            };

            let size = sect.size();

            tracing::trace!(
                "processing section with size {size}; is allocated: {}",
                sh_flags as u32 & SHF_ALLOC == SHF_ALLOC
            );

            let is_alloc = sh_flags as u32 & SHF_ALLOC == SHF_ALLOC;

            if !is_alloc {
                continue;
            }

            if size == 0 {
                // implies alloc. hence we add a gap with 1 byte alignment
                self.current_base += 1usize;
                continue;
            }

            let alignment_mask = sect.align().wrapping_sub(1);
            let address = Address::from(
                self.current_base.offset().wrapping_add(alignment_mask) & !alignment_mask,
            );
            let last_address = address + size - 1usize;

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

            self.current_base = last_address + 1usize;

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
                    .map_or_else(|| Cow::Borrowed("LOAD"), |name| Cow::Borrowed(name)),
                address,
                properties: elf_section_properties(&sect),
                bytes,
                ..Default::default()
            };

            self.covered.ranges_insert(vrange);

            relocator.apply(Address::zero(), &mut lsegm, &sect)?;

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

        let relocator = ElfSegmentRelocator::new(self.elf, self.symbols, self.is_object);

        while let Some(range) = covered.next() {
            let data = segm.data().unwrap_or_default();

            let rvsize = (*range.end() - *range.start() + 1) as usize;
            let rvstart = (*range.start() - segm.address()) as usize;
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

            let address = Address::from(*range.start());
            let last_address = address + bytes.len();

            tracing::trace!("loading segment {address}-{last_address}");

            let mut lsegm = LoadableSegment {
                name: segm
                    .name()
                    .ok()
                    .flatten()
                    .map_or_else(|| Cow::Borrowed("LOAD"), |name| Cow::Owned(name.to_owned())),
                address,
                properties: elf_segment_properties(&*segm),
                bytes,
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
        let relocator = ElfSegmentRelocator::new(self.elf, self.symbols, self.is_object);

        while let Some(sect) = self.sects.next() {
            let SectionFlags::Elf { sh_flags } = sect.flags() else {
                continue;
            };

            let size = sect.size();

            if size == 0 || (sh_flags as u32 & SHF_ALLOC) != SHF_ALLOC {
                continue;
            }

            let address = Address::from(sect.address());
            let last_address = Address::from(sect.address() + size - 1);

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
                    .map_or_else(|| Cow::Borrowed("LOAD"), |name| Cow::Borrowed(name)),
                address,
                properties: elf_section_properties(&sect),
                bytes,
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
        let relocator = ElfSegmentRelocator::new(self.elf, self.symbols, self.is_object);

        while let Some(segm) = self.segms.next() {
            let size = segm.size();

            if segm.size() == 0 {
                continue;
            }

            let address = Address::from(segm.address());
            let last_address = Address::from(segm.address() + size - 1);

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

            let address = Address::from(*range.start());
            let last_address = address + bytes.len();

            tracing::trace!("loading segment {address}-{last_address}");

            let mut lsegm = LoadableSegment {
                name: segm
                    .name()
                    .ok()
                    .flatten()
                    .map_or_else(|| Cow::Borrowed("LOAD"), |name| Cow::Owned(name.to_owned())),
                address,
                properties: elf_segment_properties(&segm),
                bytes,
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
    type Item = LoadableSegment<'data>;
    type Error = LoaderError;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.is_object {
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
    fn entry(&self) -> Option<Address> {
        Some(with_elf!(
            self.object.borrow_view(),
            elf | elf.entry().into()
        ))
    }

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

        with_elf!(
            view,
            elf | Box::new(ElfLoadableSegments::new(
                elf,
                &self.symbols,
                &self.extern_segm
            ))
                as Box<dyn FallibleIterator<Item = LoadableSegment, Error = LoaderError>>
        )
    }

    fn segment_range(&self) -> (Address, Address) {
        let start = *self.bounds.start();
        let end = *self.bounds.end();
        (start, end)
    }
}

#[cfg(test)]
mod test {
    use fallible_iterator::FallibleIterator;

    use crate::loader::Loadable;
    use crate::types::BytesOrMapping;

    use super::Elf;

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
            let elf = Elf::new(BytesOrMapping::from_file("tests/libssl.so")?)?;
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
}
