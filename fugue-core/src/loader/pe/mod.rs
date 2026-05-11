use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;
use std::path::Path;

use fallible_iterator::FallibleIterator;
use object::endian::LittleEndian as LE;
use object::pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, ImageNtHeaders32, ImageNtHeaders64,
};
use object::read::pe::{self, ImageNtHeaders, PeFile, PeSection, PeSectionIterator};
use object::{FileKind, Object, ObjectSection, ReadRef, SectionFlags};
use range_set_blaze::RangeSetBlaze;

use crate::arch::Arch;
use crate::ir::traits::SymbolTableSelector;
use crate::ir::{
    Address, ExternSegment, IndexedSymbolTable, SegmentProperties, SymbolIndex, SymbolProperties,
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
pub use analysers::PeAnalysers;

mod relocations;
pub use relocations::PeSegmentRelocator;

pub const PE_EXPORT_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(0);
pub const PE_IMPORT_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(1);

#[ouroboros::self_referencing]
struct PeInner<'a> {
    data: BytesOrMapping<'a>,
    #[borrows(data)]
    #[covariant]
    view: PeFileRepr<'this, 'a>,
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
    fn parse(data: &'this BytesOrMapping<'data>) -> Result<Self, LoaderError> {
        let pe = match FileKind::parse(data).map_err(LoaderError::format)? {
            FileKind::Pe32 => Self::Pe32(pe::PeFile32::parse(data).map_err(LoaderError::format)?),
            FileKind::Pe64 => Self::Pe64(pe::PeFile64::parse(data).map_err(LoaderError::format)?),
            _ => return Err(LoaderError::format_with("input is not a PE image")),
        };

        Ok(pe)
    }
}

pub struct Pe<'a> {
    object: PeInner<'a>,
    architecture: Arch,
    metadata: LoadableMetadata,
    base: Address,
    preferred_base: u64,
    bounds: RangeInclusive<Address>,
    mapping_hints: BTreeMap<Address, ContextHint>,
    symbols: IndexedSymbolTable,
    extern_segm: ExternSegment,
    import_slots: BTreeMap<Address, Address>,
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
        let object = PeInner::try_new(data.into(), |data| PeFileRepr::parse(data))?;
        let view = object.borrow_view();
        let language = with_pe!(view, pe | object_language(pe))?;
        let architecture = Arch::new(language);

        let attributes = attributes.into();
        let target_space = attributes.get_attr::<AddressSpaceId>(ATTRIBUTE_ADDRESS_SPACE);
        let preferred_base = with_pe!(view, pe | pe.relative_address_base());

        let base = attributes
            .get_attr::<Address>(ATTRIBUTE_IMAGE_BASE)
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

        let PeSymbolData {
            bounds,
            mapping_hints,
            symbols,
            extern_segm,
            import_slots,
        } = with_pe!(
            view,
            pe | PeSymbolData::from_pe(pe, &architecture, base, preferred_base)
        )?;

        let metadata = LoadableMetadata::new(
            object.borrow_data(),
            format!("Fugue v{} PE Loader", env!("CARGO_PKG_VERSION")),
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
            extern_segm,
            import_slots,
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
        let path = path.as_ref();
        let data = BytesOrMapping::from_file(path)?;
        let mut loaded = Self::new_with(data, attributes)?;
        loaded.metadata.set_path(path.display().to_string());
        Ok(loaded)
    }

    pub fn entry(&self) -> Option<Address> {
        let entry = with_pe!(self.object.borrow_view(), pe | pe.entry());
        (entry != 0).then(|| Address::new(self.base.space(), self.rebase_offset(entry)))
    }

    pub fn convention(&self) -> Option<&'a str> {
        None
    }

    pub fn loaded_view(&self) -> &PeFileRepr<'_, 'a> {
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

    pub fn target_space(&self) -> AddressSpaceId {
        self.base.space()
    }

    fn rebase_offset(&self, address: u64) -> u64 {
        address
            .wrapping_sub(self.preferred_base)
            .wrapping_add(self.base.offset())
    }
}

struct PeSymbolData {
    bounds: RangeInclusive<Address>,
    mapping_hints: BTreeMap<Address, ContextHint>,
    symbols: IndexedSymbolTable,
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

            let address = Address::new(
                target_space,
                sect.address()
                    .wrapping_sub(preferred_base)
                    .wrapping_add(base.offset()),
            );
            let last_address = address + sect.size() - 1usize;
            bounds = Some(match bounds {
                Some((start, end)) => (start.min(address), end.max(last_address)),
                None => (address, last_address),
            });
            sections.push((address, last_address, pe_section_properties(&sect)));
        }

        let (min_addr, max_addr) = bounds.unwrap_or((base, base));
        let extern_base = align_up(
            max_addr.offset().wrapping_add(addr_size as u64),
            addr_align as u64,
        );

        let mut symbols = IndexedSymbolTable::new();
        let mut extern_segm = ExternSegment::new(
            Address::new(target_space, extern_base),
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
            let address = Address::new(
                target_space,
                export
                    .address()
                    .wrapping_sub(preferred_base)
                    .wrapping_add(base.offset()),
            );
            let properties = symbol_properties_for_address(address, &sections)
                | SymbolProperties::LOCAL
                | SymbolProperties::EXPORT;
            symbols.insert(
                SymbolIndex::new(PE_EXPORT_SELECTOR, index),
                address,
                String::from_utf8_lossy(export.name()).into_owned(),
                properties,
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

                    let extern_address = *externs
                        .entry(name.clone())
                        .or_insert_with(|| extern_segm.add_extern());

                    symbols.insert(
                        SymbolIndex::new(PE_IMPORT_SELECTOR, import_index),
                        extern_address,
                        name,
                        SymbolProperties::EXTERN | SymbolProperties::FUNCTION,
                    );

                    let slot = Address::new(
                        target_space,
                        base.offset()
                            .wrapping_add(address_table as u64)
                            .wrapping_add((thunk_index * thunk_size) as u64),
                    );

                    import_slots.insert(slot, extern_address);

                    import_index += 1;
                    thunk_index = thunk_index.wrapping_add(1);
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

fn align_up(value: u64, alignment: u64) -> u64 {
    let mask = alignment.wrapping_sub(1);
    value.wrapping_add(mask) & !mask
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

    let mut props = SegmentProperties::LITTLE_ENDIAN;

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

struct PeLoadableSegments<'data, 'file, Pe, R>
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

impl<'data, 'file, Pe, R> PeLoadableSegments<'data, 'file, Pe, R>
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

    fn extern_segment(&mut self) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
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

        Ok(Some(LoadableSegment {
            name: Cow::Borrowed("EXTERN"),
            address,
            properties: SegmentProperties::EXTERNAL
                | SegmentProperties::PERM_READ
                | SegmentProperties::PERM_EXECUTE
                | SegmentProperties::LITTLE_ENDIAN,
            bytes: Cow::Owned(bytes),
            function_hints: Cow::Owned(externs.iter().collect::<BTreeSet<_>>()),
            ..Default::default()
        }))
    }

    fn next_section(&mut self) -> Result<Option<LoadableSegment<'data>>, LoaderError> {
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
            let last_address = address + sect.size() - 1usize;
            let vrange = address.offset()..=last_address.offset();

            if !self
                .covered
                .is_disjoint(&RangeSetBlaze::from_iter([vrange.clone()]))
            {
                tracing::debug!("overlapping PE section {address}-{last_address}; skipping");
                continue;
            }

            let data = sect.data().unwrap_or_default();
            let bytes = if data.len() as u64 != sect.size() {
                let mut data = data.to_owned();
                data.resize(sect.size() as usize, 0);
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
                properties: pe_section_properties(&sect),
                bytes,
                ..Default::default()
            };

            self.covered.ranges_insert(vrange);
            relocator.apply(&mut lsegm)?;

            return Ok(Some(lsegm));
        }

        self.extern_segment()
    }
}

impl<'data, 'file, Pe, R> FallibleIterator for PeLoadableSegments<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    type Item = LoadableSegment<'data>;
    type Error = LoaderError;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        self.next_section()
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

        with_pe!(
            view,
            pe | Box::new(PeLoadableSegments::new(
                pe,
                self.base,
                self.preferred_base,
                &self.import_slots,
                &self.extern_segm,
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

    use super::Pe;
    use crate::attributes;
    use crate::ir::Address;
    use crate::loader::{Loadable, LoadableSegment};
    use crate::types::BytesOrMapping;
    use crate::types::attributes::ATTRIBUTE_IMAGE_BASE;

    fn load_segments(
        pe: &Pe<'_>,
    ) -> Result<Vec<LoadableSegment<'static>>, Box<dyn std::error::Error>> {
        let mut segments = pe.segments();
        let mut loaded = Vec::new();

        while let Some(segm) = segments.next()? {
            loaded.push(segm.into_owned());
        }

        Ok(loaded)
    }

    fn read_u64_at(segments: &[LoadableSegment<'static>], address: Address) -> Option<u64> {
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
        assert!(pe.symbols().iter().next().is_some());
        assert!(!pe.extern_segment().is_empty());

        Ok(())
    }

    #[test]
    fn test_pe_custom_image_base() -> Result<(), Box<dyn std::error::Error>> {
        let data = BytesOrMapping::from_file("tests/hello-pe.exe")?;
        let (preferred_base, slot_address, original_value) = first_dir64_relocation(&data)?;
        let image_base = Address::from(0x1800_0000_0u64);
        let pe = Pe::new_with(data, attributes![ATTRIBUTE_IMAGE_BASE => image_base])?;
        let segments = load_segments(&pe)?;
        let rebased_address = Address::new(
            image_base.space(),
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
            .symbols()
            .iter()
            .find_map(|(_, entry)| {
                (entry.symbol().as_str() == symbol_name).then_some(entry.address())
            })
            .expect("import symbol");
        let actual = read_u64_at(&segments, Address::from(slot_address)).expect("import slot");

        assert_eq!(actual, expected.offset());

        Ok(())
    }

    #[test]
    fn test_pe_custom_image_base_without_relocations() {
        let image_base = Address::from(0x1800_0000_0u64);
        let err = match Pe::new_with(
            BytesOrMapping::from_file("tests/hello-pe-fixed.exe").expect("fixture"),
            attributes![ATTRIBUTE_IMAGE_BASE => image_base],
        ) {
            Ok(_) => panic!("rebasing fixed image should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("base relocation directory"));
    }
}
