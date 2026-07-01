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
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, ImageNtHeaders32, ImageNtHeaders64,
};
use object::read::pe::{self, ImageNtHeaders, PeFile, PeSection, PeSectionIterator};
use object::{FileKind, Object, ObjectSection, ReadRef, SectionFlags};
use range_set_blaze::RangeSetBlaze;
use smallvec::{SmallVec, smallvec};

use crate::arch::Arch;
use crate::ir::{
    Address, ExternSegment, RawAddress, RawAddressRangeSet, SegmentProperties, SymbolIndex,
    SymbolProperties, SymbolTable, SymbolTableSelector,
};
use crate::lifter::ContextHint;
use crate::loader::pe::extensions::ImageContext;
use crate::loader::{
    DefaultBankWrites, ImageAddress, ImageBacking, ImageBank, ImageBankHandle, ImageLayout,
    ImageSegment, ImageSegmentBytes, ImageSegmentIterator, ImageSpace, ImageSpaceHandle,
    ImageWrite, ImageWriteIterator, Loadable, LoadableAnalysers, LoadableFromBytes,
    LoadableFromFile, LoadableMetadata, LoaderError,
};
use crate::storage::segments::mapping::SegmentMappingProvenance;
use crate::storage::segments::space::AddressSpaceId;
use crate::types::attributes::{
    ATTRIBUTE_ADDRESS_SPACE, ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_IMAGE_BASE,
};
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

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub(crate) struct PeLoaderProperties: u8 {
        const PERMISSIVE = 0b0000_0001;
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

        config
    }

    pub(crate) fn is_permissive(&self) -> bool {
        self.contains(Self::PERMISSIVE)
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
    ) -> Result<Self, (BytesOrMapping<'a>, LoaderError)> {
        Self::try_new_or_recover(data, |data| PeLoadedRepr::parse(data, attributes))
            .map_err(|(error, heads)| (heads.data, error))
    }
}

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
            Err(failed) => failed,
        };

        if !config.is_permissive() {
            return Err(error);
        }

        let space = attributes.get_attr::<AddressSpaceId>(ATTRIBUTE_ADDRESS_SPACE);
        let Some(repaired) = permissive::try_repair(data, space)? else {
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
        let path = path.as_ref();
        let data = BytesOrMapping::from_file(path)?;
        let mut loaded = Self::new_with(data, attributes)?;
        loaded.path = Some(path.display().to_string());
        Ok(loaded)
    }

    pub fn entry(&self) -> Option<Address> {
        let loaded = self.object.borrow_loaded();
        let state = &loaded.state;
        let entry = with_pe!(&loaded.view, pe | pe.entry());
        (entry != 0).then(|| Address::new(state.base.space(), state.rebase_offset(entry)))
    }

    pub fn convention(&self) -> Option<&'a str> {
        None
    }

    pub fn loaded_view(&self) -> &PeFileRepr<'_, 'a> {
        &self.object.borrow_loaded().view
    }

    pub fn mapping_hints(&self) -> &BTreeMap<Address, ContextHint> {
        &self.object.borrow_loaded().state.mapping_hints
    }

    pub fn image_symbols(&self) -> &SymbolTable<ImageAddress> {
        &self.object.borrow_loaded().state.symbols
    }

    pub fn extern_segment(&self) -> &ExternSegment {
        &self.object.borrow_loaded().state.extern_segm
    }

    pub fn target_space(&self) -> AddressSpaceId {
        self.object.borrow_loaded().state.base.space()
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
    bank_base: RawAddress,
    base: Address,
    preferred_base: u64,
    entry: Option<ImageAddress>,
    layout: ImageLayout,
    mapping_hints: BTreeMap<Address, ContextHint>,
    symbols: SymbolTable<ImageAddress>,
    extern_segm: ExternSegment,
    import_slots: BTreeMap<Address, Address>,
    segments: Vec<PeImageSegment>,
}

impl PeLoadState {
    fn from_view(
        view: &PeFileRepr<'_, '_>,
        attributes: &AttributeMap,
    ) -> Result<Self, LoaderError> {
        let target_space = attributes.get_attr::<AddressSpaceId>(ATTRIBUTE_ADDRESS_SPACE);
        let preferred_base = with_pe!(view, pe | pe.relative_address_base());

        let base = attributes
            .get_attr::<RawAddress>(ATTRIBUTE_IMAGE_BASE)
            .map(|addr| Address::in_space(addr, target_space))
            .unwrap_or_else(|| Address::in_space(preferred_base, target_space));

        if base.offset() != preferred_base {
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
                    .checked_sub(preferred_base)
                    .and_then(|offset| base.checked_add(offset))
                    .ok_or_else(|| LoaderError::address_overflow(base))?,
            )
        } else {
            None
        };
        let image_entry = entry.map(|entry| ImageAddress::in_default_space(entry.offset()));
        let context = ImageContext::new(
            view,
            base,
            Address::new(base.space(), preferred_base),
            entry,
            attributes,
        );
        let architecture = context.resolve_architecture()?;

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
        let bank_base: RawAddress = (*bounds.start()).into();
        let bank_size = bounds
            .end()
            .checked_offset_from(*bounds.start())
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| LoaderError::address_overflow(base))?;

        let (placements, spaces) = with_pe!(
            view,
            pe | {
                let mut walk =
                    PeSegmentWalk::new(pe, base, preferred_base, bank_base, &extern_segm);
                let mut placements = Vec::new();
                while let Some(placement) = walk.next_segment()? {
                    placements.push(placement);
                }
                let spaces = walk.into_spaces();
                (placements, spaces)
            }
        );

        let mut symbol_indices_by_offset =
            BTreeMap::<RawAddress, SmallVec<[SymbolIndex; 1]>>::new();
        for (index, symbol) in &symbols {
            symbol_indices_by_offset
                .entry(symbol.address.into())
                .or_default()
                .push(*index);
        }

        let mut space_by_index = BTreeMap::<SymbolIndex, ImageSpaceHandle>::new();
        for placement in &placements {
            let start = placement.address.offset();
            let Some(last) = start.checked_add(placement.size.saturating_sub(1) as u64) else {
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

        let mut image_symbols = SymbolTable::<ImageAddress>::new();
        for (index, symbol) in symbols {
            let space = space_by_index.get(&index).copied().unwrap_or_default();
            image_symbols.insert(
                index,
                ImageAddress::new(space, symbol.address),
                symbol.name,
                symbol.properties,
            );
        }

        let layout = ImageLayout::new(
            smallvec![ImageBank::new(
                ImageBankHandle::default(),
                RawAddress::zero()..bank_size.into(),
            )],
            spaces,
        );

        Ok(Self {
            architecture,
            bank_base,
            base,
            preferred_base,
            entry: image_entry,
            layout,
            mapping_hints,
            symbols: image_symbols,
            extern_segm,
            import_slots,
            segments: placements,
        })
    }

    fn rebase_offset(&self, address: u64) -> u64 {
        address
            .wrapping_sub(self.preferred_base)
            .wrapping_add(self.base.offset())
    }
}

struct RawPeSymbol {
    address: Address,
    name: String,
    properties: SymbolProperties,
}

struct PeSymbolData {
    bounds: RangeInclusive<Address>,
    mapping_hints: BTreeMap<Address, ContextHint>,
    symbols: BTreeMap<SymbolIndex, RawPeSymbol>,
    extern_segm: ExternSegment,
    import_slots: BTreeMap<Address, Address>,
}

impl PeSymbolData {
    fn from_pe<'data, Pe, R>(
        pe: &PeFile<'data, Pe, R>,
        arch: &Arch,
        base: Address,
        preferred_base: u64,
    ) -> Result<Self, LoaderError>
    where
        Pe: ImageNtHeaders,
        R: ReadRef<'data>,
    {
        let target_space = base.space();
        let addr_size = arch.language().address_size();
        let addr_align = arch.language().address_alignment().max(addr_size);

        let mut bounds = None::<(Address, Address)>;
        let mut sections = Vec::new();

        for sect in pe.sections() {
            if sect.size() == 0 {
                continue;
            }

            let address = sect
                .address()
                .checked_sub(preferred_base)
                .and_then(|offset| base.checked_add(offset))
                .ok_or_else(|| LoaderError::address_overflow(base))?;
            let last_address = address
                .checked_add(sect.size().wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(base))?;
            bounds = Some(match bounds {
                Some((start, end)) => (start.min(address), end.max(last_address)),
                None => (address, last_address),
            });
            sections.push((address, last_address, pe_section_properties(&sect)));
        }

        let (min_addr, max_addr) = bounds.unwrap_or((base, base));
        let extern_base = max_addr
            .offset()
            .checked_add(addr_size as u64)
            .ok_or_else(|| LoaderError::address_overflow(base))?;
        let align_mask = (addr_align as u64).wrapping_sub(1);
        let aligned_extern_base = extern_base.wrapping_add(align_mask) & !align_mask;

        if aligned_extern_base < extern_base {
            return Err(LoaderError::address_overflow(base));
        }

        let mut symbols = BTreeMap::<SymbolIndex, RawPeSymbol>::new();
        let mut extern_segm = ExternSegment::new(
            Address::new(target_space, aligned_extern_base),
            addr_align,
            arch.external_thunk_template(),
        );
        let mut import_slots = BTreeMap::new();
        let mut externs = BTreeMap::<String, Address>::new();

        for (index, export) in pe
            .exports()
            .map_err(LoaderError::format)?
            .into_iter()
            .enumerate()
        {
            let address = export
                .address()
                .checked_sub(preferred_base)
                .and_then(|offset| base.checked_add(offset))
                .ok_or_else(|| LoaderError::address_overflow(base))?;
            let properties = symbol_properties_for_address(address, &sections)
                | SymbolProperties::LOCAL
                | SymbolProperties::EXPORT;
            symbols.insert(
                SymbolIndex::new(PE_EXPORT_SELECTOR, index),
                RawPeSymbol {
                    address,
                    name: String::from_utf8_lossy(export.name()).into_owned(),
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

                    let extern_address = match externs.entry(name.clone()) {
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
                            name,
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
    address: Address,
    sections: &[(Address, Address, SegmentProperties)],
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

pub fn pe_section_properties<'data, Pe, R>(sect: &PeSection<'data, '_, Pe, R>) -> SegmentProperties
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

struct PeImageSegmentBytes<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pe: &'file PeFile<'data, Pe, R>,
    sects: PeSectionIterator<'data, 'file, Pe, R>,
    covered: RangeSetBlaze<u64>,
    current_base: Address,
    preferred_base: u64,
    import_slots: &'file BTreeMap<Address, Address>,
    extern_segm: Option<&'file ExternSegment>,
}

impl<'data, 'file, Pe, R> PeImageSegmentBytes<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn new(
        pe: &'file PeFile<'data, Pe, R>,
        current_base: Address,
        preferred_base: u64,
        import_slots: &'file BTreeMap<Address, Address>,
        extern_segm: &'file ExternSegment,
    ) -> Self {
        Self {
            pe,
            sects: pe.sections(),
            covered: RangeSetBlaze::new(),
            current_base,
            preferred_base,
            import_slots,
            extern_segm: Some(extern_segm),
        }
    }

    fn relocator(&self) -> PeSegmentRelocator<'data, 'file, Pe, R> {
        PeSegmentRelocator::new(
            self.pe,
            self.preferred_base,
            self.current_base,
            self.import_slots,
        )
    }

    fn extern_segment(&mut self) -> Result<Option<ImageSegmentBytes<'data>>, LoaderError> {
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

        let bytes = externs
            .iter()
            .flat_map(|_| {
                let mut bytes = externs.template().bytes().to_vec();
                bytes.resize(bytes.len() + extern_padding, 0);
                bytes
            })
            .collect::<Vec<_>>();

        self.covered
            .ranges_insert(address.offset()..=last_address.offset());

        Ok(Some(ImageSegmentBytes::new(
            address,
            SegmentProperties::EXTERNAL
                | SegmentProperties::PERM_READ
                | SegmentProperties::PERM_EXECUTE,
            Cow::Owned(bytes),
        )))
    }

    fn next_section(&mut self) -> Result<Option<ImageSegmentBytes<'data>>, LoaderError> {
        let relocator = self.relocator();

        for sect in self.sects.by_ref() {
            if sect.size() == 0 {
                continue;
            }

            let address = Address::new(
                self.current_base.space(),
                sect.address()
                    .wrapping_sub(self.preferred_base)
                    .wrapping_add(self.current_base.offset()),
            );
            let last_address = address
                .checked_add(sect.size().wrapping_sub(1))
                .ok_or_else(|| LoaderError::address_overflow(self.current_base))?;

            if last_address < address {
                tracing::debug!("section bounds {address}-{last_address} overflow; skipping");
                continue;
            }

            let vrange = address.offset()..=last_address.offset();

            if !self
                .covered
                .is_disjoint(&RangeSetBlaze::from_iter([vrange.clone()]))
            {
                tracing::debug!("overlapping PE section {address}-{last_address}; skipping");
                continue;
            }

            let data = sect.data().unwrap_or_default();
            let emit = (data.len() as u64).min(sect.size()) as usize;

            let mut bytes =
                ImageSegmentBytes::new(address, pe_section_properties(&sect), &data[..emit]);

            self.covered.ranges_insert(vrange);
            relocator.apply(&mut bytes)?;

            return Ok(Some(bytes));
        }

        self.extern_segment()
    }
}

impl<'data, 'file, Pe, R> FallibleIterator for PeImageSegmentBytes<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    type Error = LoaderError;
    type Item = ImageSegmentBytes<'data>;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        self.next_section()
    }
}

struct PeRegion<'data> {
    name: Cow<'data, str>,
    address: Address,
    size: usize,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
}

struct PeImageSegment {
    name: String,
    address: ImageAddress,
    backing_offset: RawAddress,
    size: usize,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
}

impl PeImageSegment {
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
    base: Address,
    preferred_base: u64,
    bank_base: RawAddress,
    base_space: ImageSpaceHandle,
    sects: PeSectionIterator<'data, 'file, Pe, R>,
    extern_segm: Option<&'file ExternSegment>,
    covered: RawAddressRangeSet,
    spaces: SmallVec<[ImageSpace; 4]>,
}

impl<'data, 'file, Pe, R> PeSegmentWalk<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    fn new(
        pe: &'file PeFile<'data, Pe, R>,
        base: Address,
        preferred_base: u64,
        bank_base: RawAddress,
        extern_segm: &'file ExternSegment,
    ) -> Self {
        let base_space = ImageSpaceHandle::default();
        Self {
            base,
            preferred_base,
            bank_base,
            base_space,
            sects: pe.sections(),
            extern_segm: Some(extern_segm),
            covered: RawAddressRangeSet::new(),
            spaces: smallvec![ImageSpace::base(base_space, ImageBankHandle::default())],
        }
    }

    fn into_spaces(self) -> SmallVec<[ImageSpace; 4]> {
        self.spaces
    }

    fn next_region(&mut self) -> Result<Option<PeRegion<'data>>, LoaderError> {
        for sect in self.sects.by_ref() {
            if sect.size() == 0 {
                continue;
            }

            let address = Address::new(
                self.base.space(),
                sect.address()
                    .wrapping_sub(self.preferred_base)
                    .wrapping_add(self.base.offset()),
            );
            let size = usize::try_from(sect.size()).map_err(LoaderError::format)?;
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
            }));
        }

        Ok(self.next_extern_region())
    }

    fn next_extern_region(&mut self) -> Option<PeRegion<'data>> {
        let externs = self
            .extern_segm
            .take()
            .filter(|externs| !externs.is_empty())?;
        Some(PeRegion {
            name: Cow::Borrowed("EXTERN"),
            address: externs.address(),
            size: externs.size(),
            properties: SegmentProperties::EXTERNAL
                | SegmentProperties::PERM_READ
                | SegmentProperties::PERM_EXECUTE,
            provenance: SegmentMappingProvenance::Extern,
        })
    }

    fn next_segment(&mut self) -> Result<Option<PeImageSegment>, LoaderError> {
        let Some(region) = self.next_region()? else {
            return Ok(None);
        };
        let PeRegion {
            name,
            address,
            size,
            properties,
            provenance,
        } = region;

        let last = address
            .checked_add(size.saturating_sub(1) as u64)
            .ok_or_else(|| LoaderError::address_overflow(address))?;
        let backing_offset = address
            .checked_sub(self.bank_base)
            .ok_or_else(|| LoaderError::address_overflow(address))?;
        let range: RangeInclusive<RawAddress> = address.into()..=last.into();
        let overlaps = self.covered.intersects_range(range.clone());

        let space = if overlaps {
            let handle = ImageSpaceHandle::new(self.spaces.len() as u16);
            self.spaces
                .push(ImageSpace::overlay(handle, self.base_space));
            handle
        } else {
            self.base_space
        };

        self.covered.insert_range(range);

        Ok(Some(PeImageSegment {
            name: name.into_owned(),
            address: ImageAddress::new(space, address),
            backing_offset: backing_offset.into(),
            size,
            properties,
            provenance,
        }))
    }
}

struct PeImageSegments<'a> {
    segments: std::slice::Iter<'a, PeImageSegment>,
    mapping_space: AddressSpaceId,
    mapping_hints: &'a BTreeMap<Address, ContextHint>,
    image_symbols: &'a SymbolTable<ImageAddress>,
}

impl<'a> PeImageSegments<'a> {
    fn new(
        segments: &'a [PeImageSegment],
        mapping_space: AddressSpaceId,
        mapping_hints: &'a BTreeMap<Address, ContextHint>,
        image_symbols: &'a SymbolTable<ImageAddress>,
    ) -> Self {
        Self {
            segments: segments.iter(),
            mapping_space,
            mapping_hints,
            image_symbols,
        }
    }

    fn image_segment(&self, segment: &'a PeImageSegment) -> ImageSegment<'a> {
        let seg_start = segment.address.offset();
        let seg_last = seg_start.checked_add(segment.size.saturating_sub(1) as u64);

        let (mapping_hints, function_hints) = match seg_last {
            Some(seg_last) => {
                let mapping_hints = self
                    .mapping_hints
                    .range(
                        Address::new(self.mapping_space, seg_start)
                            ..=Address::new(self.mapping_space, seg_last),
                    )
                    .map(|(addr, hint)| (addr.offset().into(), hint.clone()))
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
            }
            None => (BTreeMap::new(), BTreeSet::new()),
        };

        ImageSegment::new(
            Cow::Borrowed(segment.name.as_str()),
            segment.address,
            segment.size,
            segment.properties,
        )
        .with_backing(ImageBacking::in_default_bank(segment.backing_offset))
        .with_provenance(segment.provenance)
        .with_mapping_hints(Cow::Owned(mapping_hints))
        .with_function_hints(Cow::Owned(function_hints))
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
        Self::from_file_with(path, attributes)
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

    fn image_symbols(&self) -> Option<&SymbolTable<ImageAddress>> {
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
            state.base.space(),
            &state.mapping_hints,
            &state.symbols,
        )) as ImageSegmentIterator<'b>
    }

    fn image_layout(&self) -> &ImageLayout {
        &self.object.borrow_loaded().state.layout
    }

    fn image_writes<'b>(
        &'b self,
    ) -> impl FallibleIterator<Item = ImageWrite<'b>, Error = LoaderError> + 'b {
        let loaded = self.object.borrow_loaded();
        let view = &loaded.view;
        let state = &loaded.state;

        with_pe!(
            view,
            pe | Box::new(DefaultBankWrites::new(
                PeImageSegmentBytes::new(
                    pe,
                    state.base,
                    state.preferred_base,
                    &state.import_slots,
                    &state.extern_segm,
                ),
                state.bank_base,
            )) as ImageWriteIterator<'b>
        )
    }

    fn analysers(&self) -> impl LoadableAnalysers {
        PeAnalysers::new(self)
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;

    use fallible_iterator::FallibleIterator;
    use object::endian::LittleEndian as LE;
    use object::pe::{IMAGE_REL_BASED_DIR64, ImageNtHeaders64};
    use object::read::pe::{Import, PeFile64};
    use object::{Object, ObjectSection};

    use super::{ATTRIBUTE_PERMISSIVE, Pe};
    use crate::attributes;
    use crate::ir::{Address, RawAddress, SegmentProperties};
    use crate::loader::{
        ImageAddress, ImageBacking, ImageBankHandle, ImageSegmentBytes, Loadable, LoaderError,
    };
    use crate::types::BytesOrMapping;
    use crate::types::attributes::ATTRIBUTE_IMAGE_BASE;

    struct LoadedSegment {
        address: ImageAddress,
        backing: ImageBacking,
        properties: SegmentProperties,
        size: usize,
    }

    struct Placement {
        address: Address,
        properties: SegmentProperties,
    }

    impl LoadedSegment {
        fn resolve(&self, bank: ImageBankHandle, offset: u64) -> Option<Placement> {
            if self.backing.bank() != bank {
                return None;
            }

            let start = self.backing.offset().offset();
            let end = start.checked_add(self.size as u64)?;
            if offset < start || offset >= end {
                return None;
            }

            let delta = offset - start;
            let address = Address::from(self.address.offset().offset().wrapping_add(delta));
            Some(Placement {
                address,
                properties: self.properties,
            })
        }
    }

    fn load_segments(
        pe: &Pe<'_>,
    ) -> Result<Vec<ImageSegmentBytes<'static>>, Box<dyn std::error::Error>> {
        let mut segments = Vec::new();
        let mut image_segments = pe.image_segments();
        while let Some(segment) = image_segments.next()? {
            if let Some(backing) = segment.backing() {
                segments.push(LoadedSegment {
                    address: segment.address(),
                    backing,
                    properties: segment.properties(),
                    size: segment.size(),
                });
            }
        }

        let mut writes = pe.image_writes();
        let mut loaded = Vec::new();

        while let Some(write) = writes.next()? {
            let placement = segments
                .iter()
                .find_map(|segment| segment.resolve(write.bank(), write.offset().offset()))
                .unwrap_or_else(|| Placement {
                    address: Address::from(write.offset().offset()),
                    properties: SegmentProperties::PERM_ALL,
                });

            loaded.push(ImageSegmentBytes::new(
                placement.address,
                placement.properties,
                write.bytes().to_owned(),
            ));
        }

        Ok(loaded)
    }

    fn read_u64_at(segments: &[ImageSegmentBytes<'static>], address: Address) -> Option<u64> {
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
    fn test_pe_exe() -> Result<(), Box<dyn std::error::Error>> {
        let pe = Pe::new(BytesOrMapping::from_file("tests/hello-pe.exe")?)?;
        let segments = load_segments(&pe)?;

        assert!(!segments.is_empty());
        assert!(pe.image_symbols().iter().next().is_some());
        assert!(!pe.extern_segment().is_empty());

        Ok(())
    }

    #[test]
    fn test_pe_custom_image_base() -> Result<(), Box<dyn std::error::Error>> {
        let data = BytesOrMapping::from_file("tests/hello-pe.exe")?;
        let (preferred_base, slot_address, original_value) = first_dir64_relocation(&data)?;
        let image_base = RawAddress::from(0x1800_0000_0u64);
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
        let image_base = RawAddress::from(0x1800_0000_0u64);
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
