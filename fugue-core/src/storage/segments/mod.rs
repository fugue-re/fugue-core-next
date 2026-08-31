use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufReader, BufWriter};
use std::mem;
use std::path::{Path, PathBuf};

use fallible_iterator::FallibleIterator;
use rkyv::rancor::Error as RkyvError;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{Address, AddressRange, AddressRangeExt, RawAddress};
use crate::lifter::ContextHint;
use crate::loader::{
    ImageAddress, ImageBankHandle, ImageResolution, ImageSpaceHandle, ImageSpaceKind, Loadable,
    LoaderError,
};
use crate::storage::PERSISTENT;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;
use crate::types::{AttributeMap, Revision};

pub(crate) mod cache;
pub(crate) mod mapping;
pub(crate) mod overlay;
pub(crate) mod properties;
pub(crate) mod provider;
pub(crate) mod space;
pub(crate) mod view;

pub use cache::SegmentMappingCache;
pub use mapping::{
    SegmentMapping, SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId,
    SegmentMappingKind, SegmentMappingProvenance, SegmentMappingRef, SegmentSubMapping,
};
pub use properties::SegmentProperties;
pub use provider::{
    InMemorySegmentStorage, MemoryMappedSegmentStorage, SegmentStorageDescriptor,
    SegmentStorageProvider, SegmentStorageProviderDescriptor, SegmentStorageProviderEntry,
    SegmentStorageProviderFromLoadable, SegmentStorageProviderFromSegmentRange,
    SegmentStorageProviderFromStorage, SegmentStorageProviderId, SegmentStorageProviderRegistry,
};
pub use space::{AddressSpace, AddressSpaceError, AddressSpaceId, AddressSpaceKind};
pub use view::SegmentMappingView;

pub type DefaultPersistentSegmentStorage = MemoryMappedSegmentStorage<{ super::PERSISTENT }>;
pub type DefaultTransientSegmentStorage = InMemorySegmentStorage;

pub const DEFAULT_SPACE_ID: AddressSpaceId = AddressSpaceId::new(0);
const DEFAULT_FILL_BYTE: u8 = 0;

const SEGMENT_STORAGE_FILE: &str = "segment.storage.bin";

#[derive(Debug, Error)]
pub enum SegmentStorageError {
    #[error("address space overflow: {0}")]
    AddressSpaceOverflow(#[from] space::AddressSpaceError),
    #[error("storage error: {0}")]
    Backing(anyhow::Error),
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid address range")]
    InvalidAddressRange,
    #[error("bank {0} has an empty or inverted address range")]
    InvalidBankRange(ImageBankHandle),
    #[error("invalid size")]
    InvalidSize,
    #[error(transparent)]
    Loader(#[from] LoaderError),
    #[error("mapping {0} is already in address space {1}")]
    MappingAlreadyInSpace(SegmentMappingId, AddressSpaceId),
    #[error("mapping {0} is not in address space {1}")]
    MappingNotInSpace(SegmentMappingId, AddressSpaceId),
    #[error("persisted overlay references unknown base space {0}")]
    MissingOverlayBase(AddressSpaceId),
    #[error("no project path specified")]
    NoProjectPath,
    #[error("failed to load project data from `{0}`: {1}")]
    ProjectData(PathBuf, io::ErrorKind),
    #[error("image segment at {0} has no backing")]
    UnbackedSegment(ImageAddress),
    #[error("image references undeclared bank {0}")]
    UnknownBank(ImageBankHandle),
    #[error("image references undeclared space {0}")]
    UnknownImageSpace(ImageSpaceHandle),
    #[error("unknown mapping {0}")]
    UnknownMapping(SegmentMappingId),
    #[error("unknown provider {0}")]
    UnknownProvider(SegmentStorageProviderId),
    #[error("unknown address space {0}")]
    UnknownSpace(AddressSpaceId),
}

impl SegmentStorageError {
    pub fn backing<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Backing(anyhow::Error::from(e))
    }

    pub fn backing_with<M>(msg: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        Self::Backing(anyhow::Error::msg(msg))
    }

    pub fn project_data(path: impl Into<PathBuf>, kind: io::ErrorKind) -> Self {
        Self::ProjectData(path.into(), kind)
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct ProviderMetadata {
    id: SegmentStorageProviderId,
    stable_tag: String,
    permissions: SegmentProperties,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct AddressSpaceMetadata {
    id: AddressSpaceId,
    kind: AddressSpaceKind,
    mapping_ids: Vec<SegmentMappingId>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct MappingMetadata {
    id: SegmentMappingId,
    name: String,
    range: AddressRange,
    physical_offset: u64,
    properties: SegmentProperties,
    kind: SegmentMappingKind,
    provenance: SegmentMappingProvenance,
    flags: SegmentMappingFlags,
    mapping_hints: BTreeMap<RawAddress, ContextHint>,
    function_hints: BTreeSet<RawAddress>,
    provider_id: SegmentStorageProviderId,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct SegmentStorageMetadata {
    providers: Vec<ProviderMetadata>,
    spaces: Vec<AddressSpaceMetadata>,
    mappings: Vec<MappingMetadata>,
    fill_byte: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpacePriority {
    Top,
    Bottom,
}

pub struct SegmentStorage {
    providers: BTreeMap<SegmentStorageProviderId, SegmentStorageDescriptor>,
    mappings: BTreeMap<SegmentMappingId, SegmentMapping>,
    spaces: BTreeMap<AddressSpaceId, AddressSpace>,
    fill_byte: u8,
    provider_ctr: usize,
    mapping_ctr: usize,
    space_ctr: usize,
    revision: Revision,
    persisted_revision: Revision,
    path: Option<PathBuf>,
}

impl Default for SegmentStorage {
    fn default() -> Self {
        Self::empty()
    }
}

pub struct LoadedSegmentStorage {
    storage: SegmentStorage,
    resolution: ImageResolution,
}

impl LoadedSegmentStorage {
    fn new(storage: SegmentStorage, resolution: ImageResolution) -> Self {
        Self {
            storage,
            resolution,
        }
    }

    pub fn storage(&self) -> &SegmentStorage {
        &self.storage
    }

    pub fn resolution(&self) -> &ImageResolution {
        &self.resolution
    }

    pub fn into_parts(self) -> (SegmentStorage, ImageResolution) {
        (self.storage, self.resolution)
    }
}

impl SegmentStorage {
    pub fn empty() -> Self {
        let mut spaces = BTreeMap::new();
        spaces.insert(DEFAULT_SPACE_ID, AddressSpace::new(DEFAULT_SPACE_ID));

        Self {
            providers: BTreeMap::new(),
            mappings: BTreeMap::new(),
            spaces,
            fill_byte: DEFAULT_FILL_BYTE,
            provider_ctr: 0,
            mapping_ctr: 0,
            space_ctr: 1,
            revision: Revision::default(),
            persisted_revision: Revision::default(),
            path: None,
        }
    }

    pub fn from_loadable<S>(
        loader: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<LoadedSegmentStorage, SegmentStorageError>
    where
        S: SegmentStorageProviderFromLoadable + 'static,
    {
        if let Some(project_path) = attributes.get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            && S::PERSISTENCE == PERSISTENT
        {
            let meta_path = project_path.join(SEGMENT_STORAGE_FILE);

            if meta_path.exists() {
                tracing::debug!(
                    "segment storage already exists at {}; loading from storage",
                    meta_path.display()
                );
                let storage = Self::from_storage_internal(&project_path, attributes)?;
                return Ok(LoadedSegmentStorage::new(
                    storage,
                    ImageResolution::default(),
                ));
            }
        }

        let mut storage = Self::empty();
        let layout = loader.image_layout();
        let mut resolution = ImageResolution::default();

        for (index, bank) in layout.banks().iter().enumerate() {
            let range = bank.range();
            if !matches!(range.size(), Some(size) if size > 0) {
                return Err(SegmentStorageError::InvalidBankRange(bank.handle()));
            }
            let start = Address::new(DEFAULT_SPACE_ID, *range.start());
            let last = Address::new(DEFAULT_SPACE_ID, *range.end());
            let provider = S::from_segment_range(
                SegmentStorageProviderId::new(index),
                start..=last,
                attributes,
            )?;
            let provider_id = storage.open_provider(provider, SegmentProperties::PERM_ALL);
            resolution.insert_bank(bank.handle(), provider_id);
        }

        let mut reuse_default = storage.spaces.len() == 1
            && storage
                .spaces
                .get(&DEFAULT_SPACE_ID)
                .map(|space| space.priority_list().next().is_none())
                .unwrap_or_default();

        let mut space_ids = Vec::with_capacity(layout.spaces().len());
        for space in layout.spaces() {
            let space_id = if reuse_default && matches!(space.kind(), ImageSpaceKind::Base { .. }) {
                reuse_default = false;
                DEFAULT_SPACE_ID
            } else {
                AddressSpaceId::try_from(storage.space_ctr)?
            };
            storage.space_ctr = storage.space_ctr.max(space_id.index() + 1);
            resolution.insert_space(space.handle(), space_id);
            space_ids.push(space_id);
        }

        for (space, &space_id) in layout.spaces().iter().zip(&space_ids) {
            let kind = match space.kind() {
                ImageSpaceKind::Base { .. } => AddressSpaceKind::Base,
                ImageSpaceKind::Overlay { base } => AddressSpaceKind::Overlay {
                    base: resolution
                        .resolve_space(base)
                        .ok_or(SegmentStorageError::UnknownImageSpace(base))?,
                },
            };
            storage
                .spaces
                .insert(space_id, AddressSpace::new_with(space_id, kind));
        }

        let bank_bases = layout
            .banks()
            .iter()
            .map(|bank| (bank.handle(), *bank.range().start()))
            .collect::<BTreeMap<ImageBankHandle, RawAddress>>();

        let space_banks = layout
            .spaces()
            .iter()
            .filter_map(|space| match space.kind() {
                ImageSpaceKind::Base { bank: Some(bank) } => Some((space.handle(), bank)),
                _ => None,
            })
            .collect::<BTreeMap<ImageSpaceHandle, ImageBankHandle>>();

        let mut discovered_hints = BTreeSet::<RawAddress>::new();
        let mut discovered_mapping_hints = BTreeMap::<RawAddress, ContextHint>::new();

        let mut contents = loader.image_contents();

        while let Some(mut content) = contents.next()? {
            discovered_hints.extend(content.take_function_hints());
            discovered_mapping_hints.extend(content.take_mapping_hints());

            let bank_base = *bank_bases
                .get(&content.bank())
                .ok_or(SegmentStorageError::UnknownBank(content.bank()))?;
            let writes = content.into_writes(bank_base)?;
            for write in writes {
                let provider_id = resolution
                    .resolve_bank(write.bank())
                    .ok_or(SegmentStorageError::UnknownBank(write.bank()))?;
                storage.write_bytes_direct(provider_id, write.offset().offset(), write.bytes())?;
            }
        }

        let mut segments = loader.image_segments();

        while let Some(segment) = segments.next()? {
            let address = resolution.resolve_address(segment.address()).ok_or(
                SegmentStorageError::UnknownImageSpace(segment.address().space()),
            )?;
            let (provider_bank, backing_offset) = match segment.backing() {
                Some(backing) => (backing.bank(), backing.offset().offset()),
                None => {
                    let bank = space_banks
                        .get(&segment.address().space())
                        .copied()
                        .ok_or(SegmentStorageError::UnbackedSegment(segment.address()))?;
                    let bank_base = *bank_bases
                        .get(&bank)
                        .ok_or(SegmentStorageError::UnknownBank(bank))?;
                    (bank, (address.raw_address() - bank_base).offset())
                }
            };
            let provider_id = resolution
                .resolve_bank(provider_bank)
                .ok_or(SegmentStorageError::UnknownBank(provider_bank))?;
            let size = segment.size();
            let properties = segment.properties();
            let provenance = segment.provenance();
            let (name, segment_mapping_hints, segment_function_hints) =
                segment.into_name_and_hints();

            let start = address.raw_address();
            let end = address.raw_address() + size;

            let extra_hints = discovered_hints.range(start..end).copied();
            let extra_mapping_hints = discovered_mapping_hints
                .range(start..end)
                .map(|(offset, hint)| (*offset, hint.clone()));

            let mapping_id = storage.create_mapping_from_builder(
                SegmentMappingBuilder::new(address, size, backing_offset, provider_id)
                    .with_properties(properties)
                    .with_name(name)
                    .with_provenance(provenance)
                    .with_mapping_hints(
                        segment_mapping_hints.into_iter().chain(extra_mapping_hints),
                    )
                    .with_function_hints(segment_function_hints.into_iter().chain(extra_hints)),
            )?;

            storage.add_mapping_to_space(address.space(), mapping_id)?;
        }

        if let Some(project_path) = attributes.get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            && storage.is_persistable()
        {
            storage.path = Some(project_path);
            storage.persist_storage()?;
        }

        Ok(LoadedSegmentStorage::new(storage, resolution))
    }

    pub fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        let path = path.as_ref();
        let meta_path = path.join(SEGMENT_STORAGE_FILE);

        if !meta_path.exists() {
            return Err(SegmentStorageError::project_data(
                path,
                io::ErrorKind::NotFound,
            ));
        }

        Self::from_storage_internal(path, attributes)
    }

    fn from_storage_internal(
        path: &Path,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        let mut metadata = Self::load_storage_metadata(path)?;
        let mut storage = Self::empty();

        for prov_meta in mem::take(&mut metadata.providers) {
            tracing::debug!(
                "loading segment storage provider `{}` with tag `{}`",
                prov_meta.id,
                prov_meta.stable_tag
            );
            let provider = SegmentStorageProviderRegistry::get().from_storage(
                &prov_meta.stable_tag,
                &prov_meta.id.path_in(path),
                attributes,
            )?;
            tracing::debug!(
                "opening segment storage provider `{}` with tag `{}`",
                prov_meta.id,
                prov_meta.stable_tag
            );

            storage.open_boxed_provider(
                prov_meta.id,
                provider,
                prov_meta.permissions,
                prov_meta.stable_tag,
            );
        }

        storage.fill_byte = metadata.fill_byte;
        storage.spaces.clear();

        if !metadata
            .spaces
            .iter()
            .any(|space| space.id == DEFAULT_SPACE_ID)
        {
            return Err(SegmentStorageError::backing_with(
                "segment metadata has no default address space",
            ));
        }

        for space_meta in &metadata.spaces {
            if storage.spaces.contains_key(&space_meta.id) {
                return Err(SegmentStorageError::backing_with(format!(
                    "duplicate address space id `{}` in segment metadata",
                    space_meta.id
                )));
            }

            let kind = match space_meta.kind {
                AddressSpaceKind::Base => AddressSpaceKind::Base,
                AddressSpaceKind::Overlay { base } => AddressSpaceKind::Overlay { base },
            };

            storage
                .spaces
                .insert(space_meta.id, AddressSpace::new_with(space_meta.id, kind));
            storage.space_ctr = storage.space_ctr.max(space_meta.id.index() + 1);
        }

        if !matches!(
            storage
                .spaces
                .get(&DEFAULT_SPACE_ID)
                .map(AddressSpace::kind),
            Some(AddressSpaceKind::Base)
        ) {
            return Err(SegmentStorageError::backing_with(
                "default address space must be a base space",
            ));
        }

        for space in storage.spaces.values() {
            if let AddressSpaceKind::Overlay { base } = space.kind()
                && !storage.spaces.contains_key(&base)
            {
                return Err(SegmentStorageError::MissingOverlayBase(base));
            }
        }

        let mut mapping_map = BTreeMap::new();
        for mapping_meta in &metadata.mappings {
            let mapping_size = mapping_meta.range.size();
            if AddressRange::from_size(mapping_meta.range.start_address(), mapping_size)
                != Some(mapping_meta.range)
            {
                return Err(SegmentStorageError::InvalidAddressRange);
            }
            let provider_id = mapping_meta.provider_id;
            if !storage.providers.contains_key(&provider_id) {
                return Err(SegmentStorageError::backing_with(format!(
                    "unknown provider `{provider_id}` in metadata"
                )));
            }
            let space_id = mapping_meta.range.space();
            if !storage.spaces.contains_key(&space_id) {
                return Err(SegmentStorageError::backing_with(
                    "unknown space in mapping metadata",
                ));
            }
            let mapping_id = storage.create_mapping_from_builder(
                SegmentMappingBuilder::new(
                    mapping_meta.range.start_address(),
                    mapping_size,
                    mapping_meta.physical_offset,
                    provider_id,
                )
                .with_properties(mapping_meta.properties)
                .with_name(mapping_meta.name.clone())
                .with_kind(mapping_meta.kind)
                .with_provenance(mapping_meta.provenance)
                .with_flags(mapping_meta.flags)
                .with_mapping_hints(mapping_meta.mapping_hints.clone())
                .with_function_hints(mapping_meta.function_hints.clone()),
            )?;

            mapping_map.insert(mapping_meta.id, mapping_id);
        }

        for space_meta in &metadata.spaces {
            let space_id = space_meta.id;
            for mapping_id in &space_meta.mapping_ids {
                let mapping_id = *mapping_map.get(mapping_id).ok_or_else(|| {
                    SegmentStorageError::backing_with(format!(
                        "unknown mapping `{mapping_id}` in space metadata"
                    ))
                })?;
                storage.add_mapping_to_space_top(space_id, mapping_id)?;
            }
        }

        storage.path = Some(path.to_owned());
        storage.persisted_revision = storage.revision;

        Ok(storage)
    }

    pub(crate) fn contains_provider(&self, id: SegmentStorageProviderId) -> bool {
        self.providers.contains_key(&id)
    }

    pub(crate) fn provider_size(&self, id: SegmentStorageProviderId) -> Option<u64> {
        self.providers.get(&id).map(SegmentStorageDescriptor::size)
    }

    pub fn fill_byte(&self) -> u8 {
        self.fill_byte
    }

    pub fn set_fill_byte(&mut self, byte: u8) {
        self.fill_byte = byte;
        self.touch();
    }

    pub fn mapping(&self, id: SegmentMappingId) -> Option<&SegmentMapping> {
        self.mappings.get(&id)
    }

    pub(crate) fn mapping_space_ids(&self, id: SegmentMappingId) -> SmallVec<[AddressSpaceId; 4]> {
        self.spaces
            .values()
            .filter(|space| space.contains_mapping(id))
            .map(AddressSpace::id)
            .collect()
    }

    pub fn spaces(&self) -> impl Iterator<Item = &AddressSpace> {
        self.spaces.values()
    }

    pub(crate) fn space_revision(&self, space_id: AddressSpaceId) -> Option<Revision> {
        self.spaces.get(&space_id).map(AddressSpace::revision)
    }

    pub fn base_space(&self, space_id: AddressSpaceId) -> Option<AddressSpaceId> {
        self.spaces.get(&space_id).and_then(AddressSpace::base)
    }

    pub fn overlay_spaces(
        &self,
        base_space_id: AddressSpaceId,
    ) -> impl Iterator<Item = AddressSpaceId> + '_ {
        self.spaces
            .values()
            .filter(move |space| space.base() == Some(base_space_id))
            .map(AddressSpace::id)
    }

    pub fn is_overlay_space(&self, space_id: AddressSpaceId) -> bool {
        self.spaces
            .get(&space_id)
            .is_some_and(AddressSpace::is_overlay)
    }

    pub fn contains_mapping(&self, at: impl Into<Address>) -> bool {
        let at = at.into();
        if let Some(space) = self.spaces.get(&at.space()) {
            space.find_containing(at).is_some()
        } else {
            false
        }
    }

    pub fn contains_mapping_in_space(
        &self,
        space_id: AddressSpaceId,
        at: impl Into<RawAddress>,
    ) -> bool {
        let at = Address::new(space_id, at.into());
        if let Some(space) = self.spaces.get(&space_id) {
            space.find_containing(at).is_some()
        } else {
            false
        }
    }

    fn is_persistable(&self) -> bool {
        self.providers.values().all(|p| {
            SegmentStorageProviderRegistry::get()
                .by_tag(p.stable_tag())
                .is_some_and(|reg| reg.is_persistable())
        })
    }

    fn is_transient(&self) -> bool {
        !self.is_persistable()
    }

    pub fn mapping_placements(
        &self,
        id: SegmentMappingId,
    ) -> impl Iterator<Item = (AddressSpaceId, (RawAddress, RawAddress))> + '_ {
        self.mappings.get(&id).into_iter().flat_map(move |mapping| {
            let range = (mapping.start().raw_address(), mapping.last().raw_address());
            self.spaces
                .values()
                .filter_map(move |space| space.contains_mapping(id).then_some((space.id(), range)))
        })
    }

    pub fn function_hints(&self) -> impl Iterator<Item = Address> + '_ {
        self.spaces.values().flat_map(move |space| {
            space.iter().flat_map(move |submap| {
                self.mappings
                    .get(&submap.mapping_ref().mapping_id())
                    .into_iter()
                    .flat_map(move |mapping| {
                        mapping.function_hints().filter_map(move |address| {
                            let mapped = Address::new(space.id(), address.raw_address());
                            submap.contains(mapped).then_some(mapped)
                        })
                    })
            })
        })
    }

    pub fn views_covering(
        &self,
        addr: impl Into<Address>,
    ) -> Result<impl Iterator<Item = SegmentMappingView<'_>> + '_, SegmentStorageError> {
        let addr = addr.into();
        self.views_covering_in_space(addr.space(), addr)
    }

    pub fn views_covering_in_space(
        &self,
        space_id: AddressSpaceId,
        addr: impl Into<RawAddress>,
    ) -> Result<impl Iterator<Item = SegmentMappingView<'_>> + '_, SegmentStorageError> {
        let addr = Address::new(space_id, addr.into());
        let space = self
            .spaces
            .get(&space_id)
            .ok_or(SegmentStorageError::InvalidAddress)?;
        let point = AddressRange::point(addr);
        let mappings = space.mappings_overlapping(point);

        Ok(mappings.into_iter().rev().filter_map(move |mapping_ref| {
            let mapping = self.mappings.get(&mapping_ref.mapping_id())?;
            let mapping_range =
                AddressRange::new(space_id, mapping.range().start(), mapping.range().end());
            if !mapping_ref.is_valid(mapping) || !mapping_range.contains_address(addr) {
                return None;
            }

            let provider = self.providers.get(&mapping.provider_id())?;
            let range = AddressRange::new(space_id, addr.raw_address(), mapping_range.end());

            Some(SegmentMappingView::from_parts(
                mapping,
                provider,
                mapping_ref,
                range,
                self.fill_byte,
            ))
        }))
    }

    pub fn views_covering_range(
        &self,
        range: AddressRange,
    ) -> Result<impl Iterator<Item = SegmentMappingView<'_>> + '_, SegmentStorageError> {
        let space_id = range.space();
        let space = self
            .spaces
            .get(&space_id)
            .ok_or(SegmentStorageError::InvalidAddress)?;
        let mappings = space.mappings_overlapping(range);

        Ok(mappings.into_iter().rev().filter_map(move |mapping_ref| {
            let mapping = self.mappings.get(&mapping_ref.mapping_id())?;
            let mapping_range =
                AddressRange::new(space_id, mapping.range().start(), mapping.range().end());
            if !mapping_ref.is_valid(mapping) || !mapping_range.intersects(&range) {
                return None;
            }

            let provider = self.providers.get(&mapping.provider_id())?;
            let submap = AddressRange::new(
                space_id,
                mapping_range.start().max(range.start()),
                mapping_range.end().min(range.end()),
            );

            Some(SegmentMappingView::from_parts(
                mapping,
                provider,
                mapping_ref,
                submap,
                self.fill_byte,
            ))
        }))
    }

    pub fn iter_views(
        &self,
        space_id: AddressSpaceId,
    ) -> Result<impl Iterator<Item = SegmentMappingView<'_>> + '_, SegmentStorageError> {
        self.iter_views_from(space_id, None)
    }

    pub fn iter_views_from(
        &self,
        space_id: AddressSpaceId,
        start: Option<Address>,
    ) -> Result<impl Iterator<Item = SegmentMappingView<'_>> + '_, SegmentStorageError> {
        let space = self
            .spaces
            .get(&space_id)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let views = space.iter_from(start).map(|submap| {
            let mapping_ref = submap.mapping_ref();
            let mapping = self
                .mappings
                .get(&mapping_ref.mapping_id())
                .expect("mapping should exist");
            let provider = self
                .providers
                .get(&mapping.provider_id())
                .expect("provider should exist");

            SegmentMappingView::new(mapping, provider, submap, self.fill_byte)
        });

        Ok(views)
    }

    pub fn mapping_properties(&self, at: impl Into<Address>) -> Option<SegmentProperties> {
        let at = at.into();
        self.mapping_properties_in_space(at.space(), at)
    }

    pub fn mapping_properties_in_space(
        &self,
        space_id: AddressSpaceId,
        at: impl Into<RawAddress>,
    ) -> Option<SegmentProperties> {
        let at = Address::new(space_id, at.into());
        let space = self.spaces.get(&space_id)?;
        let submap = space.find_containing(at)?;
        let mapping = self.mappings.get(&submap.mapping_ref().mapping_id())?;
        submap
            .mapping_ref()
            .is_valid(mapping)
            .then(|| mapping.properties())
    }

    pub(crate) fn persist_storage(&mut self) -> Result<(), SegmentStorageError> {
        if self.is_transient() {
            tracing::debug!("segment storage is transient; skipping persistence");
            return Ok(());
        }

        let Some(meta_path) = self.path.as_ref().map(|p| p.join(SEGMENT_STORAGE_FILE)) else {
            tracing::debug!("segment storage has no project path; skipping persistence");
            return Ok(());
        };

        if self.persisted_revision == self.revision {
            tracing::debug!(
                "segment storage metadata unchanged at revision {}; skipping persistence",
                self.revision.value()
            );
            return Ok(());
        }

        tracing::debug!("persisting segment storage to {}", meta_path.display());

        let providers = self
            .providers
            .values()
            .map(|p| {
                tracing::debug!(
                    "persisting segment storage provider `{}` with tag `{}`",
                    p.id(),
                    p.stable_tag(),
                );
                ProviderMetadata {
                    id: p.id(),
                    stable_tag: p.stable_tag().to_owned(),
                    permissions: p.permissions(),
                }
            })
            .collect::<Vec<_>>();

        let spaces = self
            .spaces
            .values()
            .map(|b| AddressSpaceMetadata {
                id: b.id(),
                kind: b.kind(),
                mapping_ids: b.priority_list().map(|r| r.mapping_id()).collect(),
            })
            .collect::<Vec<_>>();

        let mappings = self
            .mappings
            .values()
            .map(|m| MappingMetadata {
                id: m.id(),
                name: m.name().to_owned(),
                range: m.range(),
                physical_offset: m.offset(),
                properties: m.properties(),
                kind: m.kind(),
                provenance: m.provenance(),
                flags: m.flags(),
                mapping_hints: m.mapping_hint_offsets().clone(),
                function_hints: m.function_hint_offsets().clone(),
                provider_id: m.provider_id(),
            })
            .collect::<Vec<_>>();

        let metadata = SegmentStorageMetadata {
            providers,
            spaces,
            mappings,
            fill_byte: self.fill_byte,
        };

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&metadata).map_err(|e| {
            SegmentStorageError::backing_with(format!("failed to encode metadata: {e}"))
        })?;

        let file = File::create(&meta_path)
            .map_err(|e| SegmentStorageError::project_data(&meta_path, e.kind()))?;
        let mut writer = BufWriter::new(file);

        io::Write::write_all(&mut writer, &bytes).map_err(|e| {
            SegmentStorageError::backing_with(format!("failed to write metadata: {e}"))
        })?;
        writer
            .into_inner()
            .map_err(|e| {
                SegmentStorageError::backing_with(format!("failed to flush metadata: {e}"))
            })?
            .sync_all()
            .map_err(|e| {
                SegmentStorageError::backing_with(format!("failed to synchronise metadata: {e}"))
            })?;

        self.persisted_revision = self.revision;

        Ok(())
    }

    fn load_storage_metadata(
        path: impl AsRef<Path>,
    ) -> Result<SegmentStorageMetadata, SegmentStorageError> {
        let meta_path = path.as_ref().join(SEGMENT_STORAGE_FILE);

        tracing::debug!("loading segment storage from {}", meta_path.display());

        let file = File::open(&meta_path)
            .map_err(|e| SegmentStorageError::project_data(&meta_path, e.kind()))?;
        let mut reader = BufReader::new(file);

        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut reader, &mut bytes).map_err(|e| {
            SegmentStorageError::backing_with(format!("failed to read metadata: {e}"))
        })?;
        let metadata =
            rkyv::from_bytes::<SegmentStorageMetadata, RkyvError>(&bytes).map_err(|e| {
                SegmentStorageError::backing_with(format!("failed to decode metadata: {e}"))
            })?;

        tracing::debug!(
            "loaded segment storage metadata; {} providers, {} spaces, {} mappings",
            metadata.providers.len(),
            metadata.spaces.len(),
            metadata.mappings.len(),
        );

        Ok(metadata)
    }

    pub fn open_provider<S>(
        &mut self,
        provider: S,
        permissions: SegmentProperties,
    ) -> SegmentStorageProviderId
    where
        S: SegmentStorageProviderDescriptor + 'static,
    {
        let id = SegmentStorageProviderId::new(self.provider_ctr);
        self.provider_ctr += 1;

        let descriptor = SegmentStorageDescriptor::new(id, provider, permissions);
        self.providers.insert(id, descriptor);
        self.touch();

        id
    }

    pub(crate) fn open_boxed_provider(
        &mut self,
        id: SegmentStorageProviderId,
        provider: Box<dyn SegmentStorageProvider>,
        permissions: SegmentProperties,
        stable_tag: impl Into<Cow<'static, str>>,
    ) -> SegmentStorageProviderId {
        self.provider_ctr = self.provider_ctr.max(id.index() + 1);

        let descriptor =
            SegmentStorageDescriptor::from_boxed(id, provider, permissions, stable_tag);
        self.providers.insert(id, descriptor);
        self.touch();

        id
    }

    pub fn close_provider(
        &mut self,
        id: SegmentStorageProviderId,
    ) -> Result<(), SegmentStorageError> {
        let mapping_ids_to_remove = self
            .mappings
            .iter()
            .filter(|(_, m)| m.provider_id() == id)
            .map(|(&mid, _)| mid)
            .collect::<SmallVec<[_; 8]>>();

        for mapping_id in mapping_ids_to_remove {
            self.remove_mapping(mapping_id)?;
        }

        self.providers
            .remove(&id)
            .ok_or(SegmentStorageError::UnknownProvider(id))?;
        self.touch();

        Ok(())
    }

    pub fn create_mapping(
        &mut self,
        provider_id: SegmentStorageProviderId,
        start: impl Into<Address>,
        size: u64,
        offset: u64,
        properties: SegmentProperties,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        if !self.providers.contains_key(&provider_id) {
            return Err(SegmentStorageError::UnknownProvider(provider_id));
        }

        let range = AddressRange::from_size(start.into(), size)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;

        let id = SegmentMappingId::new(self.mapping_ctr);
        self.mapping_ctr += 1;

        let mapping = SegmentMapping::new(id, range, offset, provider_id, properties)?;
        self.mappings.insert(id, mapping);
        self.touch();

        Ok(id)
    }

    pub fn create_mapping_from_builder(
        &mut self,
        builder: SegmentMappingBuilder,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        if !self.providers.contains_key(&builder.provider_id()) {
            return Err(SegmentStorageError::UnknownProvider(builder.provider_id()));
        }

        let id = SegmentMappingId::new(self.mapping_ctr);
        let mapping = SegmentMapping::from_builder(id, builder)?;
        self.mapping_ctr += 1;

        self.mappings.insert(id, mapping);
        self.touch();

        Ok(id)
    }

    pub(crate) fn create_mapping_with_id(
        &mut self,
        id: SegmentMappingId,
        builder: SegmentMappingBuilder,
    ) -> Result<(), SegmentStorageError> {
        if !self.providers.contains_key(&builder.provider_id()) {
            return Err(SegmentStorageError::UnknownProvider(builder.provider_id()));
        }
        if self.mappings.contains_key(&id) {
            return Err(SegmentStorageError::backing_with("mapping already exists"));
        }

        let mapping = SegmentMapping::from_builder(id, builder)?;
        self.mapping_ctr = self.mapping_ctr.max(id.index() + 1);
        self.mappings.insert(id, mapping);
        self.touch();
        Ok(())
    }

    pub(crate) fn pending_mapping_id(
        &self,
        offset: usize,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        let index = self
            .mapping_ctr
            .checked_add(offset)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping id exhausted"))?;
        SegmentMappingId::try_from(index)
            .map_err(|_| SegmentStorageError::backing_with("mapping id exhausted"))
    }

    pub fn remove_mapping(&mut self, id: SegmentMappingId) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&id)
            .ok_or(SegmentStorageError::UnknownMapping(id))?;
        let range = mapping.range();
        let spaces = self.mapping_space_ids(id);

        for space_id in spaces {
            self.remove_mapping_from_space(space_id, id, range)?;
        }

        self.mappings
            .remove(&id)
            .expect("mapping existence was checked before removal");
        self.touch();

        Ok(())
    }

    pub fn remap_mapping(
        &mut self,
        id: SegmentMappingId,
        new_start: impl Into<Address>,
    ) -> Result<(), SegmentStorageError> {
        let new_start = new_start.into();

        let mapping = self
            .mappings
            .get_mut(&id)
            .ok_or(SegmentStorageError::UnknownMapping(id))?;

        let old_range = mapping.range();
        mapping.set_start(new_start)?;
        let mapping_ref = mapping.mapping_ref();
        let new_range = mapping.range();
        let spaces = self.mapping_space_ids(id);

        for space_id in spaces {
            self.update_mapping_in_space(space_id, mapping_ref, old_range, new_range)?;
        }
        self.touch();

        Ok(())
    }

    pub fn resize_mapping(
        &mut self,
        id: SegmentMappingId,
        new_size: u64,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get_mut(&id)
            .ok_or(SegmentStorageError::UnknownMapping(id))?;

        let old_range = mapping.range();
        mapping.set_size(new_size)?;
        let mapping_ref = mapping.mapping_ref();
        let new_range = mapping.range();
        let spaces = self.mapping_space_ids(id);

        for space_id in spaces {
            self.update_mapping_in_space(space_id, mapping_ref, old_range, new_range)?;
        }
        self.touch();

        Ok(())
    }

    pub fn update_mapping_metadata(
        &mut self,
        id: SegmentMappingId,
        kind: SegmentMappingKind,
        provenance: SegmentMappingProvenance,
        flags: SegmentMappingFlags,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get_mut(&id)
            .ok_or(SegmentStorageError::UnknownMapping(id))?;

        let range = mapping.range();
        mapping.update_metadata(kind, provenance, flags);
        let mapping_ref = mapping.mapping_ref();
        let spaces = self.mapping_space_ids(id);

        for space_id in spaces {
            self.update_mapping_in_space(space_id, mapping_ref, range, range)?;
        }
        self.touch();

        Ok(())
    }

    pub fn create_space(&mut self) -> Result<AddressSpaceId, SegmentStorageError> {
        let id = AddressSpaceId::try_from(self.space_ctr)?;
        self.space_ctr += 1;
        self.spaces.insert(id, AddressSpace::new(id));
        self.touch();
        Ok(id)
    }

    pub(crate) fn create_space_with_id(
        &mut self,
        id: AddressSpaceId,
    ) -> Result<(), SegmentStorageError> {
        if self.spaces.contains_key(&id) {
            return Err(SegmentStorageError::backing_with(
                "address space already exists",
            ));
        }

        self.space_ctr = self.space_ctr.max(id.index() + 1);
        self.spaces.insert(id, AddressSpace::new(id));
        self.touch();
        Ok(())
    }

    pub(crate) fn pending_space_id(
        &self,
        offset: usize,
    ) -> Result<AddressSpaceId, SegmentStorageError> {
        let index = self
            .space_ctr
            .checked_add(offset)
            .ok_or_else(|| SegmentStorageError::backing_with("address space id exhausted"))?;
        AddressSpaceId::try_from(index).map_err(Into::into)
    }

    pub fn add_mapping_to_space(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&mapping_id)
            .ok_or(SegmentStorageError::UnknownMapping(mapping_id))?;

        match mapping.provenance() {
            SegmentMappingProvenance::Segment
            | SegmentMappingProvenance::FileResidue
            | SegmentMappingProvenance::Synthetic => {
                self.add_mapping_to_space_bottom(space_id, mapping_id)
            }
            _ => self.add_mapping_to_space_top(space_id, mapping_id),
        }
    }

    pub fn add_mapping_to_space_top(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.add_mapping_to_space_at(space_id, mapping_id, SpacePriority::Top)
    }

    pub fn add_mapping_to_space_bottom(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        self.add_mapping_to_space_at(space_id, mapping_id, SpacePriority::Bottom)
    }

    fn add_mapping_to_space_at(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
        priority: SpacePriority,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&mapping_id)
            .ok_or(SegmentStorageError::UnknownMapping(mapping_id))?;

        let mapping_ref = mapping.mapping_ref();
        let start = mapping.start();
        let size = mapping.size();
        let properties = mapping.properties();

        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or(SegmentStorageError::UnknownSpace(space_id))?;
        if space.contains_mapping(mapping_id) {
            return Err(SegmentStorageError::MappingAlreadyInSpace(
                mapping_id, space_id,
            ));
        }

        match priority {
            SpacePriority::Top => space.add_mapping_top(mapping_ref, start, size, properties),
            SpacePriority::Bottom => space.add_mapping_bottom(mapping_ref, start, size, properties),
        }
        self.touch();

        Ok(())
    }

    pub fn prioritise_mapping(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&mapping_id)
            .ok_or(SegmentStorageError::UnknownMapping(mapping_id))?;
        let mapping_ref = mapping.mapping_ref();
        let start = mapping.start();
        let size = mapping.size();
        let properties = mapping.properties();

        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or(SegmentStorageError::UnknownSpace(space_id))?;
        if !space.contains_mapping(mapping_id) {
            return Err(SegmentStorageError::MappingNotInSpace(mapping_id, space_id));
        }
        space.add_mapping_top(mapping_ref, start, size, properties);
        self.touch();
        Ok(())
    }

    pub fn deprioritise_mapping(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        if !self.mappings.contains_key(&mapping_id) {
            return Err(SegmentStorageError::UnknownMapping(mapping_id));
        }

        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or(SegmentStorageError::UnknownSpace(space_id))?;
        if !space.contains_mapping(mapping_id) {
            return Err(SegmentStorageError::MappingNotInSpace(mapping_id, space_id));
        }

        space.deprioritise(mapping_id);
        self.touch();

        self.rebuild_submaps_for_mapping(space_id, mapping_id)
    }

    fn rebuild_submaps_for_mapping(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&mapping_id)
            .ok_or(SegmentStorageError::UnknownMapping(mapping_id))?;

        self.rebuild_submaps_in_range(space_id, mapping.range())
    }

    fn update_mapping_in_space(
        &mut self,
        space_id: AddressSpaceId,
        mapping_ref: SegmentMappingRef,
        old_range: AddressRange,
        new_range: AddressRange,
    ) -> Result<(), SegmentStorageError> {
        self.spaces
            .get_mut(&space_id)
            .ok_or(SegmentStorageError::UnknownSpace(space_id))?
            .update_mapping_ref(mapping_ref, new_range);

        self.rebuild_submaps_in_range(space_id, old_range)?;
        if new_range != old_range {
            self.rebuild_submaps_in_range(space_id, new_range)?;
        }

        Ok(())
    }

    fn remove_mapping_from_space(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
        range: AddressRange,
    ) -> Result<(), SegmentStorageError> {
        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or(SegmentStorageError::UnknownSpace(space_id))?;
        if !space.remove_mapping_ref(mapping_id) {
            return Ok(());
        }

        self.rebuild_submaps_in_range(space_id, range)
    }

    fn rebuild_submaps_in_range(
        &mut self,
        space_id: AddressSpaceId,
        range: AddressRange,
    ) -> Result<(), SegmentStorageError> {
        let range = AddressRange::new(space_id, range.start(), range.end());

        let space = self
            .spaces
            .get(&space_id)
            .ok_or(SegmentStorageError::UnknownSpace(space_id))?;

        let overlapping = space
            .mappings_overlapping(range)
            .into_iter()
            .filter_map(|mref| {
                self.mappings
                    .get(&mref.mapping_id())
                    .map(|m| (mref, m.start().raw_address(), m.size(), m.properties()))
            })
            .collect::<SmallVec<[_; 8]>>();

        let space = self
            .spaces
            .get_mut(&space_id)
            .expect("space existence was checked before rebuilding its range");
        space.rebuild_range(range, overlapping);

        Ok(())
    }

    pub fn read_bytes(
        &self,
        addr: impl Into<Address>,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        let addr = addr.into();
        self.read_bytes_in_space(addr.space(), addr, bytes)
    }

    pub fn read_bytes_in_space(
        &self,
        space_id: AddressSpaceId,
        addr: impl Into<RawAddress>,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        if bytes.is_empty() {
            return Ok(0);
        }

        let addr = Address::new(space_id, addr.into());
        let size =
            u64::try_from(bytes.len()).map_err(|_| SegmentStorageError::InvalidAddressRange)?;
        AddressRange::from_size(addr, size).ok_or(SegmentStorageError::InvalidAddressRange)?;

        let space = self
            .spaces
            .get(&space_id)
            .ok_or(SegmentStorageError::UnknownSpace(space_id))?;

        let mut current_addr = addr;
        let mut remaining = bytes.len();
        let mut total_read = 0;

        while remaining > 0 {
            let view = match space.find_containing(current_addr) {
                Some(v) => v,
                None => {
                    let skip = space.gap_len_at(current_addr, remaining);
                    let buffer_offset = usize::from(current_addr - addr);
                    bytes[buffer_offset..buffer_offset + skip].fill(self.fill_byte);
                    current_addr += skip;
                    remaining -= skip;
                    continue;
                }
            };

            let mapping_ref = view.mapping_ref();
            let view_remaining = remaining.min(
                usize::try_from(
                    view.range()
                        .remaining_from(current_addr)
                        .expect("containing view has bytes remaining"),
                )
                .unwrap_or(usize::MAX),
            );
            let buffer_offset = usize::from(current_addr - addr);
            let buffer = &mut bytes[buffer_offset..buffer_offset + view_remaining];

            if let Some((mapping, provider)) = self
                .mappings
                .get(&mapping_ref.mapping_id())
                .filter(|mapping| mapping_ref.is_valid(mapping))
                .and_then(|mapping| {
                    self.providers
                        .get(&mapping.provider_id())
                        .map(|provider| (mapping, provider))
                })
            {
                if mapping.properties().is_readable() {
                    let mapping_view =
                        SegmentMappingView::new(mapping, provider, view, self.fill_byte);
                    total_read += mapping_view.read_bytes(current_addr, buffer)?;
                } else {
                    buffer.fill(self.fill_byte);
                    total_read += view_remaining;
                }
            } else {
                buffer.fill(self.fill_byte);
                total_read += view_remaining;
            }

            current_addr += view_remaining;
            remaining -= view_remaining;
        }

        Ok(total_read)
    }

    pub fn read_bytes_direct(
        &self,
        provider_id: SegmentStorageProviderId,
        offset: u64,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        let provider = self
            .providers
            .get(&provider_id)
            .ok_or(SegmentStorageError::UnknownProvider(provider_id))?;

        provider.provider().read_bytes(offset, bytes)
    }

    pub fn write_bytes(
        &mut self,
        addr: impl Into<Address>,
        bytes: &[u8],
    ) -> Result<usize, SegmentStorageError> {
        let addr = addr.into();
        self.write_bytes_in_space(addr.space(), addr, bytes)
    }

    pub fn write_bytes_in_space(
        &mut self,
        space_id: AddressSpaceId,
        addr: impl Into<RawAddress>,
        bytes: &[u8],
    ) -> Result<usize, SegmentStorageError> {
        self.write_bytes_to_space(space_id, addr, bytes)
    }

    fn write_bytes_to_space(
        &mut self,
        space_id: AddressSpaceId,
        addr: impl Into<RawAddress>,
        bytes: &[u8],
    ) -> Result<usize, SegmentStorageError> {
        if bytes.is_empty() {
            return Ok(0);
        }

        let addr = Address::new(space_id, addr.into());
        let size =
            u64::try_from(bytes.len()).map_err(|_| SegmentStorageError::InvalidAddressRange)?;
        AddressRange::from_size(addr, size).ok_or(SegmentStorageError::InvalidAddressRange)?;

        let mut current_addr = addr;
        let mut remaining = bytes.len();
        let mut total_written = 0;
        let mut write_offset = 0;

        while remaining > 0 {
            let view = {
                let space = self
                    .spaces
                    .get(&space_id)
                    .ok_or(SegmentStorageError::UnknownSpace(space_id))?;

                match space.find_containing(current_addr) {
                    Some(v) => v,
                    None => {
                        let skip = space.gap_len_at(current_addr, remaining);
                        current_addr += skip;
                        remaining -= skip;
                        write_offset += skip;
                        continue;
                    }
                }
            };

            let mapping_ref = view.mapping_ref();
            let view_remaining = usize::try_from(
                view.range()
                    .remaining_from(current_addr)
                    .expect("containing view has bytes remaining"),
            )
            .unwrap_or(usize::MAX);
            let write_size = remaining.min(view_remaining);
            let write_data = &bytes[write_offset..write_offset + write_size];

            let mapping = match self.mappings.get_mut(&mapping_ref.mapping_id()) {
                Some(m) => m,
                None => {
                    current_addr += write_size;
                    remaining -= write_size;
                    write_offset += write_size;
                    continue;
                }
            };

            if !mapping_ref.is_valid(mapping) {
                current_addr += write_size;
                remaining -= write_size;
                write_offset += write_size;
                continue;
            }

            if !mapping.properties().is_writable() {
                current_addr += write_size;
                remaining -= write_size;
                write_offset += write_size;
                continue;
            }

            let phys_offset = mapping.to_offset(current_addr);
            let provider_id = mapping.provider_id();

            let provider = match self.providers.get_mut(&provider_id) {
                Some(p) => p,
                None => {
                    current_addr += write_size;
                    remaining -= write_size;
                    write_offset += write_size;
                    continue;
                }
            };

            let written = provider
                .provider_mut()
                .write_bytes(phys_offset, write_data)?;

            total_written += written;
            current_addr += written;
            remaining -= written;
            write_offset += written;

            if written != write_size {
                break;
            }
        }

        Ok(total_written)
    }

    pub fn write_bytes_direct(
        &mut self,
        provider_id: SegmentStorageProviderId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<usize, SegmentStorageError> {
        let provider = self
            .providers
            .get_mut(&provider_id)
            .ok_or(SegmentStorageError::UnknownProvider(provider_id))?;

        provider.provider_mut().write_bytes(offset, bytes)
    }

    pub fn read_bytes_exact(
        &self,
        addr: impl Into<Address>,
        bytes: &mut [u8],
    ) -> Result<(), SegmentStorageError> {
        if self.read_bytes(addr, bytes)? != bytes.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    pub fn write_bytes_exact(
        &mut self,
        addr: impl Into<Address>,
        bytes: &[u8],
    ) -> Result<(), SegmentStorageError> {
        if self.write_bytes(addr, bytes)? != bytes.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    pub fn resolve_to_base_address(&self, address: impl Into<Address>) -> Address {
        let address = address.into();
        self.base_space(address.space())
            .map_or(address, |space| Address::new(space, address.offset()))
    }

    pub fn resolve_to_offset(
        &self,
        addr: impl Into<Address>,
    ) -> Option<(SegmentStorageProviderId, u64)> {
        let addr = addr.into();
        let space = self.spaces.get(&addr.space())?;
        let view = space.find_containing(addr)?;
        let mapping = self.mappings.get(&view.mapping_ref().mapping_id())?;
        let offset = mapping.to_offset(addr);
        Some((mapping.provider_id(), offset))
    }

    pub fn view_containing(
        &self,
        address: impl Into<Address>,
    ) -> Result<SegmentMappingView<'_>, SegmentStorageError> {
        let address = address.into();
        self.view_containing_in_space(address.space(), address)
    }

    pub fn view_containing_in_space(
        &self,
        space_id: AddressSpaceId,
        address: impl Into<RawAddress>,
    ) -> Result<SegmentMappingView<'_>, SegmentStorageError> {
        let address = address.into();

        let space = self
            .spaces
            .get(&space_id)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let mapping_view = space
            .find_containing(address)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let mapping = self
            .mappings
            .get(&mapping_view.mapping_ref().mapping_id())
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let provider = self
            .providers
            .get(&mapping.provider_id())
            .ok_or(SegmentStorageError::InvalidAddress)?;

        Ok(SegmentMappingView::new(
            mapping,
            provider,
            mapping_view,
            self.fill_byte,
        ))
    }

    fn view_for_submapping(
        &self,
        submapping: &SegmentSubMapping,
    ) -> Result<SegmentMappingView<'_>, SegmentStorageError> {
        let mapping_ref = submapping.mapping_ref();
        let mapping = self
            .mappings
            .get(&mapping_ref.mapping_id())
            .filter(|mapping| mapping_ref.is_valid(mapping))
            .ok_or(SegmentStorageError::InvalidAddress)?;
        let provider = self
            .providers
            .get(&mapping.provider_id())
            .ok_or(SegmentStorageError::InvalidAddress)?;

        Ok(SegmentMappingView::new(
            mapping,
            provider,
            submapping,
            self.fill_byte,
        ))
    }

    fn touch(&mut self) {
        self.revision = self.revision.next();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::arch::Arch;
    use crate::ir::Endian;
    use crate::loader::{
        ImageAddress, ImageBacking, ImageBank, ImageLayout, ImageSegment, ImageSegmentContents,
        ImageSegmentContentsIterator, ImageSegmentIterator, ImageSpace, ImageSpaceHandle,
        LoadableMetadata,
    };
    use crate::storage::segments::mapping::SegmentMappingProvenance;

    struct SegSpec {
        name: &'static str,
        space: ImageSpaceHandle,
        addr: u64,
        size: u64,
        bank: ImageBankHandle,
    }

    struct ContentSpec {
        addr: u64,
        bank: ImageBankHandle,
        fill: u8,
        size: usize,
    }

    struct FakeImage {
        layout: ImageLayout,
        segments: Vec<SegSpec>,
        contents: Vec<ContentSpec>,
        metadata: LoadableMetadata,
        attributes: AttributeMap,
    }

    impl Loadable for FakeImage {
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
            unimplemented!("not exercised by from_loadable")
        }

        fn image_layout(&self) -> &ImageLayout {
            &self.layout
        }

        fn image_segments<'a>(
            &'a self,
        ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a {
            let segments = self
                .segments
                .iter()
                .map(|spec| {
                    Ok(ImageSegment::new(
                        spec.name,
                        ImageAddress::new(spec.space, spec.addr),
                        spec.size,
                        SegmentProperties::PERM_ALL,
                    )
                    .with_backing(ImageBacking::new(spec.bank, 0u64)))
                })
                .collect::<Vec<Result<ImageSegment<'a>, LoaderError>>>();
            Box::new(fallible_iterator::convert(segments.into_iter())) as ImageSegmentIterator<'a>
        }

        fn image_contents<'a>(
            &'a self,
        ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a
        {
            let contents = self
                .contents
                .iter()
                .map(|spec| {
                    let mut contents = ImageSegmentContents::new(
                        spec.addr,
                        Endian::Little,
                        vec![spec.fill; spec.size],
                    );
                    contents.set_bank(spec.bank);
                    Ok(contents)
                })
                .collect::<Vec<Result<ImageSegmentContents<'a>, LoaderError>>>();
            Box::new(fallible_iterator::convert(contents.into_iter()))
                as ImageSegmentContentsIterator<'a>
        }
    }

    struct UnbackedLoader {
        layout: ImageLayout,
        seg_space: ImageSpaceHandle,
        seg_addr: u64,
        seg_size: u64,
        content: Option<(u64, ImageBankHandle, u8, usize)>,
        metadata: LoadableMetadata,
        attributes: AttributeMap,
    }

    impl Loadable for UnbackedLoader {
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
            unimplemented!("not exercised by from_loadable")
        }

        fn image_layout(&self) -> &ImageLayout {
            &self.layout
        }

        fn image_segments<'a>(
            &'a self,
        ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a {
            let segment = ImageSegment::new(
                "seg",
                ImageAddress::new(self.seg_space, self.seg_addr),
                self.seg_size,
                SegmentProperties::PERM_ALL,
            );
            Box::new(fallible_iterator::convert(std::iter::once(Ok(segment))))
                as ImageSegmentIterator<'a>
        }

        fn image_contents<'a>(
            &'a self,
        ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a
        {
            let contents = self
                .content
                .map(|(addr, bank, fill, size)| {
                    let mut contents =
                        ImageSegmentContents::new(addr, Endian::Little, vec![fill; size]);
                    contents.set_bank(bank);
                    contents
                })
                .into_iter()
                .map(Ok)
                .collect::<Vec<_>>();
            Box::new(fallible_iterator::convert(contents.into_iter()))
                as ImageSegmentContentsIterator<'a>
        }
    }

    #[test]
    fn mapping_properties_fast_path() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();

        let text_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0x90; 4]),
            SegmentProperties::PERM_ALL,
        );
        let data_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0x00; 4]),
            SegmentProperties::PERM_ALL,
        );

        let text = SegmentProperties::PERM_READ | SegmentProperties::PERM_EXECUTE;
        let data = SegmentProperties::PERM_READ | SegmentProperties::PERM_WRITE;
        let text_id = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, text_provider)
                .with_properties(text)
                .with_name("text"),
        )?;
        let data_id = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x2000u64, 4, 0, data_provider)
                .with_properties(data)
                .with_name("data"),
        )?;

        storage.add_mapping_to_space(DEFAULT_SPACE_ID, text_id)?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, data_id)?;

        assert_eq!(storage.mapping_properties(0x1000u64), Some(text));
        assert_eq!(storage.mapping_properties(0x2003u64), Some(data));
        assert_eq!(storage.mapping_properties(0x3000u64), None);

        Ok(())
    }

    #[test]
    fn removing_shadowing_mapping_reveals_lower_mapping() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();
        let lower_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(b"abcdefgh".to_vec()),
            SegmentProperties::PERM_ALL,
        );
        let upper_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(b"WXYZ".to_vec()),
            SegmentProperties::PERM_ALL,
        );
        let lower = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 8, 0, lower_provider)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("lower"),
        )?;
        let upper = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1002u64, 4, 0, upper_provider)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("upper"),
        )?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, lower)?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, upper)?;

        let mut bytes = [0u8; 8];
        storage.read_bytes_exact(0x1000u64, &mut bytes)?;
        assert_eq!(&bytes, b"abWXYZgh");

        storage.remove_mapping(upper)?;

        storage.read_bytes_exact(0x1000u64, &mut bytes)?;
        assert_eq!(&bytes, b"abcdefgh");
        assert_eq!(storage.view_containing(0x1003u64)?.name(), "lower");
        Ok(())
    }

    #[test]
    fn moving_and_shrinking_mapping_rebuilds_its_old_extent() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();
        let lower_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(b"abcdefgh".to_vec()),
            SegmentProperties::PERM_ALL,
        );
        let upper_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(b"WXYZ".to_vec()),
            SegmentProperties::PERM_ALL,
        );
        let lower = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 8, 0, lower_provider)
                .with_properties(SegmentProperties::PERM_ALL),
        )?;
        let upper = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1002u64, 4, 0, upper_provider)
                .with_properties(SegmentProperties::PERM_ALL),
        )?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, lower)?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, upper)?;

        storage.resize_mapping(upper, 2)?;
        let mut bytes = [0u8; 8];
        storage.read_bytes_exact(0x1000u64, &mut bytes)?;
        assert_eq!(&bytes, b"abWXefgh");

        storage.remap_mapping(upper, 0x2000u64)?;
        storage.read_bytes_exact(0x1000u64, &mut bytes)?;
        assert_eq!(&bytes, b"abcdefgh");
        let mut moved = [0u8; 2];
        storage.read_bytes_exact(0x2000u64, &mut moved)?;
        assert_eq!(&moved, b"WX");
        Ok(())
    }

    #[test]
    fn test_views_covering_preserve_priority_and_provenance() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();

        let segment_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0x41, 0x42, 0x43, 0x44]),
            SegmentProperties::PERM_ALL,
        );
        let section_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0x51, 0x52, 0x53, 0x54]),
            SegmentProperties::PERM_ALL,
        );

        let segment_id = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, segment_provider)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("segment")
                .with_provenance(SegmentMappingProvenance::Segment),
        )?;
        let section_id = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, section_provider)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("section")
                .with_provenance(SegmentMappingProvenance::Section),
        )?;

        storage.add_mapping_to_space(DEFAULT_SPACE_ID, segment_id)?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, section_id)?;

        let visible = storage.view_containing(0x1000u64)?;
        assert_eq!(visible.name(), "section");
        assert_eq!(visible.provenance(), SegmentMappingProvenance::Section);

        let covering = storage.views_covering(0x1000u64)?.collect::<Vec<_>>();
        assert_eq!(covering.len(), 2);
        assert_eq!(covering[0].name(), "section");
        assert_eq!(covering[0].provenance(), SegmentMappingProvenance::Section);
        assert_eq!(covering[1].name(), "segment");
        assert_eq!(covering[1].provenance(), SegmentMappingProvenance::Segment);

        let other_space = storage.create_space()?;
        storage.add_mapping_to_space(other_space, section_id)?;
        let covering = storage
            .views_covering_in_space(other_space, 0x1000u64)?
            .collect::<Vec<_>>();
        assert_eq!(covering.len(), 1);
        assert_eq!(covering[0].space(), other_space);
        assert_eq!(covering[0].name(), "section");

        storage.update_mapping_metadata(
            section_id,
            SegmentMappingKind::Bss,
            SegmentMappingProvenance::Uninitialised,
            SegmentMappingFlags::PAGED,
        )?;

        let mut bytes = [0u8; 4];
        storage.read_bytes_exact(0x1000u64, &mut bytes)?;
        assert_eq!(&bytes, &[0x51, 0x52, 0x53, 0x54]);
        let visible = storage.view_containing(0x1000u64)?;
        assert_eq!(visible.kind(), SegmentMappingKind::Bss);
        assert_eq!(
            visible.provenance(),
            SegmentMappingProvenance::Uninitialised
        );
        assert_eq!(visible.mapping().flags(), SegmentMappingFlags::PAGED);
        assert_eq!(
            storage
                .views_covering_in_space(other_space, 0x1000u64)?
                .count(),
            1
        );

        Ok(())
    }

    #[test]
    fn test_persisted_mapping_priority_survives_reload() -> Result<(), SegmentStorageError> {
        let project = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let mut storage = SegmentStorage::empty();
        let first_provider = storage.open_provider(
            MemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(
                SegmentStorageProviderId::new(0).path_in(project.path()),
                4,
            )?,
            SegmentProperties::PERM_ALL,
        );
        let second_provider = storage.open_provider(
            MemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(
                SegmentStorageProviderId::new(1).path_in(project.path()),
                4,
            )?,
            SegmentProperties::PERM_ALL,
        );
        storage.write_bytes_direct(first_provider, 0, &[0xAA; 4])?;
        storage.write_bytes_direct(second_provider, 0, &[0xBB; 4])?;
        let first = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, first_provider)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("first")
                .with_provenance(SegmentMappingProvenance::Segment),
        )?;
        let second = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, second_provider)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("second")
                .with_provenance(SegmentMappingProvenance::Section),
        )?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, first)?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, second)?;
        storage.prioritise_mapping(DEFAULT_SPACE_ID, first)?;
        storage.path = Some(project.path().to_owned());
        storage.persist_storage()?;
        drop(storage);

        let mut attributes = AttributeMap::new();
        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project.path());
        let storage = SegmentStorage::from_storage(project.path(), &mut attributes)?;
        let mut bytes = [0u8; 4];
        storage.read_bytes_exact(0x1000u64, &mut bytes)?;

        assert_eq!(storage.view_containing(0x1000u64)?.name(), "first");
        assert_eq!(bytes, [0xAA; 4]);

        Ok(())
    }

    #[test]
    fn persisted_provider_id_gap_survives_multiple_reloads() -> Result<(), SegmentStorageError> {
        let project = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let mut storage = SegmentStorage::empty();
        let removed = storage.open_provider(
            MemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(
                SegmentStorageProviderId::new(0).path_in(project.path()),
                4,
            )?,
            SegmentProperties::PERM_ALL,
        );
        let retained = storage.open_provider(
            MemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(
                SegmentStorageProviderId::new(1).path_in(project.path()),
                4,
            )?,
            SegmentProperties::PERM_ALL,
        );
        storage.close_provider(removed)?;
        storage.write_bytes_direct(retained, 0, &[0x5a; 4])?;
        let mapping = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, retained)
                .with_properties(SegmentProperties::PERM_ALL),
        )?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, mapping)?;
        storage.path = Some(project.path().to_owned());
        storage.persist_storage()?;
        drop(storage);

        let mut attributes = AttributeMap::new();
        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project.path());
        let mut storage = SegmentStorage::from_storage(project.path(), &mut attributes)?;
        storage.path = Some(project.path().to_owned());
        storage.persist_storage()?;
        drop(storage);

        let storage = SegmentStorage::from_storage(project.path(), &mut attributes)?;
        let mut bytes = [0u8; 4];
        storage.read_bytes_exact(0x1000u64, &mut bytes)?;
        assert_eq!(bytes, [0x5a; 4]);
        Ok(())
    }

    #[test]
    fn sparse_address_space_ids_survive_reload() -> Result<(), SegmentStorageError> {
        let project = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let sparse = AddressSpaceId::new(7);
        let mut storage = SegmentStorage::empty();
        storage.create_space_with_id(sparse)?;
        storage.path = Some(project.path().to_owned());
        storage.persist_storage()?;

        let mut attributes = AttributeMap::new();
        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project.path());
        let mut storage = SegmentStorage::from_storage(project.path(), &mut attributes)?;

        assert!(storage.spaces().any(|space| space.id() == sparse));
        assert_eq!(storage.create_space()?, AddressSpaceId::new(8));
        Ok(())
    }

    #[test]
    fn fill_byte_survives_reload() -> Result<(), SegmentStorageError> {
        let project = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let mut storage = SegmentStorage::empty();
        storage.set_fill_byte(0xa5);
        storage.path = Some(project.path().to_owned());
        storage.persist_storage()?;

        let mut attributes = AttributeMap::new();
        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project.path());
        let storage = SegmentStorage::from_storage(project.path(), &mut attributes)?;
        assert_eq!(storage.fill_byte(), 0xa5);
        Ok(())
    }

    #[test]
    fn mapped_holes_use_the_storage_fill_byte() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();
        storage.set_fill_byte(0xa5);
        let provider = storage.open_provider(
            InMemorySegmentStorage::with_size(4),
            SegmentProperties::PERM_ALL,
        );
        storage.write_bytes_direct(provider, 1, &[0x12, 0x34])?;
        let mapping = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, provider)
                .with_properties(SegmentProperties::PERM_ALL),
        )?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, mapping)?;

        let mut bytes = [0x77; 4];
        storage.read_bytes_exact(0x1000u64, &mut bytes)?;
        assert_eq!(bytes, [0xa5, 0x12, 0x34, 0xa5]);
        Ok(())
    }

    #[test]
    fn uninitialised_memory_mapped_backing_uses_the_fill_byte() -> Result<(), SegmentStorageError> {
        let project = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let mut storage = SegmentStorage::empty();
        storage.set_fill_byte(0xa5);
        let provider = storage.open_provider(
            MemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(
                project.path().join("uninitialised.data"),
                4,
            )?,
            SegmentProperties::PERM_ALL,
        );
        let mapping = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, provider)
                .with_properties(SegmentProperties::PERM_ALL),
        )?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, mapping)?;

        let mut bytes = [0x77; 4];
        storage.read_bytes_exact(0x1000u64, &mut bytes)?;
        assert_eq!(bytes, [0xa5; 4]);
        Ok(())
    }

    #[test]
    fn mapped_ranges_beyond_backing_are_filled_and_counted() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();
        storage.set_fill_byte(0xa5);
        let provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0x12, 0x34]),
            SegmentProperties::PERM_ALL,
        );
        let mapping = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, provider)
                .with_properties(SegmentProperties::PERM_ALL),
        )?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, mapping)?;

        let mut mapped = [0x77; 4];
        storage.read_bytes_exact(0x1000u64, &mut mapped)?;
        assert_eq!(mapped, [0x12, 0x34, 0xa5, 0xa5]);

        let mut crossing = [0x77; 6];
        assert_eq!(storage.read_bytes(0x1000u64, &mut crossing)?, 4);
        assert_eq!(crossing, [0x12, 0x34, 0xa5, 0xa5, 0xa5, 0xa5]);
        assert!(matches!(
            storage.read_bytes_exact(0x1000u64, &mut crossing),
            Err(SegmentStorageError::InvalidAddressRange)
        ));
        Ok(())
    }

    #[test]
    fn unreadable_mappings_are_filled_and_counted() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();
        storage.set_fill_byte(0xa5);
        let provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0x12, 0x34]),
            SegmentProperties::PERM_ALL,
        );
        let mapping = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 2, 0, provider)
                .with_properties(SegmentProperties::PERM_WRITE),
        )?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, mapping)?;

        let mut bytes = [0x77; 2];
        storage.read_bytes_exact(0x1000u64, &mut bytes)?;
        assert_eq!(bytes, [0xa5; 2]);
        Ok(())
    }

    #[test]
    fn test_read_write_across_large_gap() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();

        let low = storage.open_provider(
            InMemorySegmentStorage::with_size(4),
            SegmentProperties::PERM_ALL,
        );
        let high = storage.open_provider(
            InMemorySegmentStorage::with_size(4),
            SegmentProperties::PERM_ALL,
        );

        let low_id = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, low)
                .with_properties(SegmentProperties::PERM_ALL),
        )?;
        let high_id = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x8000u64, 4, 0, high)
                .with_properties(SegmentProperties::PERM_ALL),
        )?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, low_id)?;
        storage.add_mapping_to_space(DEFAULT_SPACE_ID, high_id)?;

        let payload = [0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB];
        let mut src = vec![0u8; 0x7004];
        src[..4].copy_from_slice(&payload[..4]);
        src[0x7000..].copy_from_slice(&payload[4..]);
        assert_eq!(storage.write_bytes(0x1000u64, &src)?, 8);

        let mut buf = vec![0x77u8; 0x7004];
        let read = storage.read_bytes(0x1000u64, &mut buf)?;
        assert_eq!(read, 8);
        assert_eq!(&buf[..4], &[0xAA; 4]);
        assert!(
            buf[4..0x7000].iter().all(|byte| *byte == 0),
            "the gap reads back as the fill byte"
        );
        assert_eq!(&buf[0x7000..], &[0xBB; 4]);

        let mut overflowing = [0u8; 2];
        assert!(matches!(
            storage.read_bytes(u64::MAX, &mut overflowing),
            Err(SegmentStorageError::InvalidAddressRange)
        ));
        assert!(matches!(
            storage.write_bytes(u64::MAX, &[0u8; 2]),
            Err(SegmentStorageError::InvalidAddressRange)
        ));

        Ok(())
    }

    #[test]
    fn test_prioritise_brings_mapping_to_top() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();

        let a = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0xAA; 4]),
            SegmentProperties::PERM_ALL,
        );
        let b = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0xBB; 4]),
            SegmentProperties::PERM_ALL,
        );

        let a_id = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, a)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("a"),
        )?;
        let b_id = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, b)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("b"),
        )?;
        storage.add_mapping_to_space_top(DEFAULT_SPACE_ID, a_id)?;
        storage.add_mapping_to_space_top(DEFAULT_SPACE_ID, b_id)?;

        assert_eq!(storage.view_containing(0x1000u64)?.name(), "b");

        storage.prioritise_mapping(DEFAULT_SPACE_ID, a_id)?;

        assert_eq!(storage.view_containing(0x1000u64)?.name(), "a");
        let mut buf = [0u8; 4];
        storage.read_bytes_exact(0x1000u64, &mut buf)?;
        assert_eq!(&buf, &[0xAA; 4]);

        storage.deprioritise_mapping(DEFAULT_SPACE_ID, a_id)?;

        assert_eq!(storage.view_containing(0x1000u64)?.name(), "b");
        storage.read_bytes_exact(0x1000u64, &mut buf)?;
        assert_eq!(&buf, &[0xBB; 4]);

        Ok(())
    }

    #[test]
    fn remap_and_resize_preserve_mapping_priority() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();
        let lower_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0xaa; 4]),
            SegmentProperties::PERM_ALL,
        );
        let upper_provider = storage.open_provider(
            InMemorySegmentStorage::from_bytes(vec![0xbb; 4]),
            SegmentProperties::PERM_ALL,
        );
        let lower = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, lower_provider)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("lower"),
        )?;
        let upper = storage.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, upper_provider)
                .with_properties(SegmentProperties::PERM_ALL)
                .with_name("upper"),
        )?;
        storage.add_mapping_to_space_bottom(DEFAULT_SPACE_ID, lower)?;
        storage.add_mapping_to_space_top(DEFAULT_SPACE_ID, upper)?;

        storage.resize_mapping(lower, 3)?;
        assert_eq!(storage.view_containing(0x1000u64)?.name(), "upper");

        storage.remap_mapping(lower, 0x0fffu64)?;
        assert_eq!(storage.view_containing(0x0fffu64)?.name(), "lower");
        assert_eq!(storage.view_containing(0x1000u64)?.name(), "upper");
        assert_eq!(
            storage
                .spaces()
                .find(|space| space.id() == DEFAULT_SPACE_ID)
                .expect("default address space exists")
                .priority_list()
                .map(SegmentMappingRef::mapping_id)
                .collect::<Vec<_>>(),
            [lower, upper]
        );
        Ok(())
    }

    #[test]
    fn mapping_addition_and_priority_require_distinct_states() -> Result<(), SegmentStorageError> {
        let mut storage = SegmentStorage::empty();
        let provider = storage.open_provider(
            InMemorySegmentStorage::with_size(4),
            SegmentProperties::PERM_ALL,
        );
        let placed =
            storage.create_mapping(provider, 0x1000u64, 4, 0, SegmentProperties::PERM_ALL)?;
        let unplaced =
            storage.create_mapping(provider, 0x1000u64, 4, 0, SegmentProperties::PERM_ALL)?;
        storage.add_mapping_to_space_top(DEFAULT_SPACE_ID, placed)?;

        assert!(matches!(
            storage.add_mapping_to_space_bottom(DEFAULT_SPACE_ID, placed),
            Err(SegmentStorageError::MappingAlreadyInSpace(mapping, space))
                if mapping == placed && space == DEFAULT_SPACE_ID
        ));
        assert!(matches!(
            storage.prioritise_mapping(DEFAULT_SPACE_ID, unplaced),
            Err(SegmentStorageError::MappingNotInSpace(mapping, space))
                if mapping == unplaced && space == DEFAULT_SPACE_ID
        ));
        assert!(matches!(
            storage.deprioritise_mapping(DEFAULT_SPACE_ID, unplaced),
            Err(SegmentStorageError::MappingNotInSpace(mapping, space))
                if mapping == unplaced && space == DEFAULT_SPACE_ID
        ));
        let unknown = SegmentMappingId::new(2);
        assert!(matches!(
            storage.deprioritise_mapping(DEFAULT_SPACE_ID, unknown),
            Err(SegmentStorageError::UnknownMapping(mapping)) if mapping == unknown
        ));
        assert_eq!(
            storage
                .spaces()
                .find(|space| space.id() == DEFAULT_SPACE_ID)
                .expect("default address space exists")
                .priority_list()
                .map(SegmentMappingRef::mapping_id)
                .collect::<Vec<_>>(),
            [placed]
        );
        Ok(())
    }

    #[test]
    fn test_from_loadable_folds_discovered_function_hints() -> Result<(), SegmentStorageError> {
        struct FakeLoader {
            layout: ImageLayout,
            metadata: LoadableMetadata,
            attributes: AttributeMap,
        }

        impl Loadable for FakeLoader {
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
                unimplemented!("not exercised by from_loadable")
            }

            fn image_layout(&self) -> &ImageLayout {
                &self.layout
            }

            fn image_segments<'a>(
                &'a self,
            ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a
            {
                let segment = ImageSegment::new(
                    "seg",
                    ImageAddress::in_default_space(0x1000u64),
                    0x100,
                    SegmentProperties::PERM_ALL,
                )
                .with_backing(ImageBacking::in_default_bank(0u64));
                Box::new(fallible_iterator::convert(std::iter::once(Ok(segment))))
                    as ImageSegmentIterator<'a>
            }

            fn image_contents<'a>(
                &'a self,
            ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a
            {
                let mut contents =
                    ImageSegmentContents::new(0x1000u64, Endian::Little, vec![0u8; 0x100]);
                contents.add_function_hint(0x1040u64);
                contents.add_mapping_hint(0x1040u64, ContextHint::data());
                Box::new(fallible_iterator::convert(std::iter::once(Ok(contents))))
                    as ImageSegmentContentsIterator<'a>
            }
        }

        let layout = ImageLayout::new(
            vec![ImageBank::new(
                ImageBankHandle::default(),
                RawAddress::from(0x1000u64)..=RawAddress::from(0x10ffu64),
            )],
            vec![ImageSpace::base(ImageSpaceHandle::default())],
        );

        let loader = FakeLoader {
            layout,
            metadata: LoadableMetadata::new(b"", "test"),
            attributes: AttributeMap::new(),
        };

        let mut attributes = AttributeMap::new();
        let (storage, _resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(&loader, &mut attributes)?
                .into_parts();

        let view = storage.view_containing(0x1000u64)?;
        let hints = view.function_hints().collect::<Vec<_>>();
        assert!(
            hints.iter().any(|hint| hint.offset() == 0x1040),
            "relocation-discovered function hint should reach the covering mapping",
        );
        assert!(
            storage
                .function_hints()
                .any(|hint| hint == Address::in_default_space(0x1040u64)),
            "storage-level function hints should use mapped addresses",
        );

        assert_eq!(
            view.mapping_hint_at(0x1040u64),
            Some(&ContextHint::data()),
            "relocation-discovered mapping hint should reach the covering mapping",
        );

        Ok(())
    }

    #[test]
    fn test_from_loadable_routes_overlapping_banks() -> Result<(), SegmentStorageError> {
        const BANK_A: ImageBankHandle = ImageBankHandle::new(0);
        const BANK_B: ImageBankHandle = ImageBankHandle::new(1);
        const SPACE_A: ImageSpaceHandle = ImageSpaceHandle::new(0);
        const SPACE_B: ImageSpaceHandle = ImageSpaceHandle::new(1);
        const BASE: u64 = 0x1000;
        const SIZE: usize = 0x10;

        let range = RawAddress::from(BASE)..=RawAddress::from(BASE + SIZE as u64 - 1);
        let loader = FakeImage {
            layout: ImageLayout::new(
                vec![
                    ImageBank::new(BANK_A, range.clone()),
                    ImageBank::new(BANK_B, range),
                ],
                vec![
                    ImageSpace::base(SPACE_A),
                    ImageSpace::overlay(SPACE_B, SPACE_A),
                ],
            ),
            segments: vec![
                SegSpec {
                    name: "a",
                    space: SPACE_A,
                    addr: BASE,
                    size: SIZE as u64,
                    bank: BANK_A,
                },
                SegSpec {
                    name: "b",
                    space: SPACE_B,
                    addr: BASE,
                    size: SIZE as u64,
                    bank: BANK_B,
                },
            ],
            contents: vec![
                ContentSpec {
                    addr: BASE,
                    bank: BANK_A,
                    fill: 0xAA,
                    size: SIZE,
                },
                ContentSpec {
                    addr: BASE,
                    bank: BANK_B,
                    fill: 0xBB,
                    size: SIZE,
                },
            ],
            metadata: LoadableMetadata::new(b"", "test"),
            attributes: AttributeMap::new(),
        };

        let mut attributes = AttributeMap::new();
        let (storage, resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(&loader, &mut attributes)?
                .into_parts();

        let space_a = resolution.resolve_space(SPACE_A).expect("space a resolved");
        let space_b = resolution.resolve_space(SPACE_B).expect("space b resolved");
        assert_ne!(
            space_a, space_b,
            "overlapping spaces must not collapse to one id"
        );

        let provider_a = resolution.resolve_bank(BANK_A).expect("bank a provider");
        let provider_b = resolution.resolve_bank(BANK_B).expect("bank b provider");
        assert_ne!(
            provider_a, provider_b,
            "distinct banks need distinct providers"
        );

        let mut buf = [0u8; SIZE];
        storage.read_bytes_direct(provider_a, 0, &mut buf)?;
        assert_eq!(buf, [0xAAu8; SIZE], "bank A provider holds content A");
        storage.read_bytes_direct(provider_b, 0, &mut buf)?;
        assert_eq!(buf, [0xBBu8; SIZE], "bank B provider holds content B");

        storage.read_bytes(Address::new(space_a, BASE), &mut buf)?;
        assert_eq!(
            buf, [0xAAu8; SIZE],
            "base space reads bank A at the shared address"
        );
        storage.read_bytes(Address::new(space_b, BASE), &mut buf)?;
        assert_eq!(
            buf, [0xBBu8; SIZE],
            "overlay space reads bank B at the shared address"
        );

        Ok(())
    }

    #[test]
    fn test_from_loadable_rejects_unknown_bank() {
        const DECLARED: ImageBankHandle = ImageBankHandle::new(0);
        const UNDECLARED: ImageBankHandle = ImageBankHandle::new(7);
        const SPACE: ImageSpaceHandle = ImageSpaceHandle::new(0);
        const BASE: u64 = 0x1000;
        const SIZE: usize = 0x10;

        let loader = FakeImage {
            layout: ImageLayout::new(
                vec![ImageBank::new(
                    DECLARED,
                    RawAddress::from(BASE)..=RawAddress::from(BASE + SIZE as u64 - 1),
                )],
                vec![ImageSpace::base(SPACE)],
            ),
            segments: vec![SegSpec {
                name: "s",
                space: SPACE,
                addr: BASE,
                size: SIZE as u64,
                bank: DECLARED,
            }],
            contents: vec![ContentSpec {
                addr: BASE,
                bank: UNDECLARED,
                fill: 0xCC,
                size: SIZE,
            }],
            metadata: LoadableMetadata::new(b"", "test"),
            attributes: AttributeMap::new(),
        };

        let mut attributes = AttributeMap::new();
        let result =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(&loader, &mut attributes);
        assert!(
            matches!(result, Err(SegmentStorageError::UnknownBank(bank)) if bank == UNDECLARED),
            "content tagged with an undeclared bank must fail with UnknownBank",
        );
    }

    #[test]
    fn test_from_loadable_rejects_whole_space_bank() {
        const BANK: ImageBankHandle = ImageBankHandle::new(0);
        const SPACE: ImageSpaceHandle = ImageSpaceHandle::new(0);

        let loader = FakeImage {
            layout: ImageLayout::new(
                vec![ImageBank::new(BANK, RawAddress::zero()..=RawAddress::MAX)],
                vec![ImageSpace::base(SPACE)],
            ),
            segments: Vec::new(),
            contents: Vec::new(),
            metadata: LoadableMetadata::new(b"", "test"),
            attributes: AttributeMap::new(),
        };

        let mut attributes = AttributeMap::new();
        let result =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(&loader, &mut attributes);
        assert!(
            matches!(result, Err(SegmentStorageError::InvalidBankRange(bank)) if bank == BANK),
            "a bank spanning the whole address space has an unrepresentable size and must fail",
        );
    }

    #[test]
    fn test_from_loadable_accepts_top_of_space_bank() -> Result<(), SegmentStorageError> {
        const BANK: ImageBankHandle = ImageBankHandle::new(0);
        const SPACE: ImageSpaceHandle = ImageSpaceHandle::new(0);
        const SIZE: usize = 0x100;

        let base = u64::MAX - (SIZE as u64 - 1);
        let loader = FakeImage {
            layout: ImageLayout::new(
                vec![ImageBank::new(
                    BANK,
                    RawAddress::from(base)..=RawAddress::MAX,
                )],
                vec![ImageSpace::base(SPACE)],
            ),
            segments: vec![SegSpec {
                name: "s",
                space: SPACE,
                addr: base,
                size: SIZE as u64,
                bank: BANK,
            }],
            contents: vec![ContentSpec {
                addr: base,
                bank: BANK,
                fill: 0xCC,
                size: SIZE,
            }],
            metadata: LoadableMetadata::new(b"", "test"),
            attributes: AttributeMap::new(),
        };

        let mut attributes = AttributeMap::new();
        SegmentStorage::from_loadable::<InMemorySegmentStorage>(&loader, &mut attributes)?;

        Ok(())
    }

    #[test]
    fn test_from_loadable_base_with_bank_backs_unbacked_segment() -> Result<(), SegmentStorageError>
    {
        const BANK: ImageBankHandle = ImageBankHandle::new(0);
        const SPACE: ImageSpaceHandle = ImageSpaceHandle::new(0);
        const BASE: u64 = 0x2000;
        const SIZE: usize = 0x10;

        let loader = UnbackedLoader {
            layout: ImageLayout::new(
                vec![ImageBank::new(
                    BANK,
                    RawAddress::from(BASE)..=RawAddress::from(BASE + SIZE as u64 - 1),
                )],
                vec![ImageSpace::base_with(SPACE, BANK)],
            ),
            seg_space: SPACE,
            seg_addr: BASE,
            seg_size: SIZE as u64,
            content: Some((BASE, BANK, 0xEE, SIZE)),
            metadata: LoadableMetadata::new(b"", "test"),
            attributes: AttributeMap::new(),
        };

        let mut attributes = AttributeMap::new();
        let (storage, resolution) =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(&loader, &mut attributes)?
                .into_parts();

        let space = resolution.resolve_space(SPACE).expect("space resolved");
        let mut buf = [0u8; SIZE];
        storage.read_bytes(Address::new(space, BASE), &mut buf)?;
        assert_eq!(
            buf, [0xEEu8; SIZE],
            "an unbacked segment inherits the bank bound to its base space",
        );

        Ok(())
    }

    #[test]
    fn test_from_loadable_none_base_rejects_unbacked_segment() {
        const BANK: ImageBankHandle = ImageBankHandle::new(0);
        const SPACE: ImageSpaceHandle = ImageSpaceHandle::new(0);
        const BASE: u64 = 0x2000;
        const SIZE: usize = 0x10;

        let loader = UnbackedLoader {
            layout: ImageLayout::new(
                vec![ImageBank::new(
                    BANK,
                    RawAddress::from(BASE)..=RawAddress::from(BASE + SIZE as u64 - 1),
                )],
                vec![ImageSpace::base(SPACE)],
            ),
            seg_space: SPACE,
            seg_addr: BASE,
            seg_size: SIZE as u64,
            content: None,
            metadata: LoadableMetadata::new(b"", "test"),
            attributes: AttributeMap::new(),
        };

        let mut attributes = AttributeMap::new();
        let result =
            SegmentStorage::from_loadable::<InMemorySegmentStorage>(&loader, &mut attributes);
        assert!(
            matches!(result, Err(SegmentStorageError::UnbackedSegment(_))),
            "an unbacked segment in a bankless base space must fail with UnbackedSegment",
        );
    }
}
