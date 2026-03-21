use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufReader, BufWriter};
use std::mem;
use std::path::{Path, PathBuf};

use bincode::{Decode, Encode};
use fallible_iterator::FallibleIterator;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{Address, SegmentProperties};
use crate::lifter::ContextHint;
use crate::loader::{Loadable, LoaderError};
use crate::types::AttributeMap;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;

pub mod mapping;
pub mod overlay;
pub mod provider;
pub mod space;
pub mod view;

use mapping::{
    SegmentMapping, SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId,
    SegmentMappingKind,
};
use provider::SegmentStorageProviderRegistry;
use space::{AddressSpace, AddressSpaceId};
use view::SegmentMappingView;

pub use provider::{
    InMemorySegmentStorage, MemoryMappedSegmentStorage, PersistableSegmentStorageProvider,
    SegmentStorageDescriptor, SegmentStorageProvider, SegmentStorageProviderFromLoadable,
    SegmentStorageProviderFromSegmentRange, SegmentStorageProviderFromStorage,
    SegmentStorageProviderId,
};

pub type DefaultPersistentSegmentStorage = MemoryMappedSegmentStorage<{ super::PERSISTENT }>;
pub type DefaultTransientSegmentStorage = InMemorySegmentStorage;

const DEFAULT_SPACE_ID: AddressSpaceId = 0;
const DEFAULT_FILL_BYTE: u8 = 0;
const DEFAULT_PROVIDER_ID: SegmentStorageProviderId = 0;

const SEGMENT_STORAGE_FILE: &str = "segment.storage.bin";

#[derive(Debug, Error)]
pub enum SegmentStorageError {
    #[error("storage error: {0}")]
    Backing(anyhow::Error),
    #[error("invalid address range")]
    InvalidAddressRange,
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid size")]
    InvalidSize,
    #[error(transparent)]
    Loader(#[from] LoaderError),
    #[error("failed to load project data from `{0}`: {1}")]
    ProjectData(PathBuf, io::ErrorKind),
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

#[derive(Encode, Decode)]
struct ProviderMetadata {
    id: SegmentStorageProviderId,
    stable_tag: String,
    permissions: SegmentProperties,
}

#[derive(Encode, Decode)]
struct AddressSpaceMetadata {
    id: AddressSpaceId,
    mapping_ids: Vec<SegmentMappingId>,
}

#[derive(Encode, Decode)]
struct MappingMetadata {
    name: String,
    virtual_start: u64,
    physical_offset: u64,
    size: usize,
    properties: SegmentProperties,
    kind: SegmentMappingKind,
    flags: SegmentMappingFlags,
    mapping_hints: BTreeMap<Address, ContextHint>,
    function_hints: BTreeSet<Address>,
    space_id: AddressSpaceId,
    provider_id: SegmentStorageProviderId,
}

#[derive(Encode, Decode)]
struct SegmentStorageMetadata {
    providers: Vec<ProviderMetadata>,
    spaces: Vec<AddressSpaceMetadata>,
    mappings: Vec<MappingMetadata>,
}

pub struct SegmentStorage {
    providers: BTreeMap<SegmentStorageProviderId, SegmentStorageDescriptor>,
    mappings: BTreeMap<SegmentMappingId, SegmentMapping>,
    spaces: BTreeMap<AddressSpaceId, AddressSpace>,
    current_space: AddressSpaceId,
    fill_byte: u8,
    next_provider_id: SegmentStorageProviderId,
    next_mapping_id: SegmentMappingId,
    next_space_id: AddressSpaceId,
}

impl Default for SegmentStorage {
    fn default() -> Self {
        Self::empty()
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
            current_space: DEFAULT_SPACE_ID,
            fill_byte: DEFAULT_FILL_BYTE,
            next_provider_id: DEFAULT_PROVIDER_ID,
            next_mapping_id: 0,
            next_space_id: 1,
        }
    }

    pub fn from_loadable<S>(
        loader: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError>
    where
        S: SegmentStorageProviderFromLoadable + PersistableSegmentStorageProvider + 'static,
    {
        if let Some(project_path) = attributes.get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH) {
            let meta_path = project_path.join(SEGMENT_STORAGE_FILE);

            if meta_path.exists() {
                tracing::debug!(
                    "segment storage already exists at {}; loading from storage",
                    meta_path.display()
                );
                return Self::from_storage_internal(&project_path, attributes);
            }
        }

        let bounds = loader.segment_bounds();
        let mut storage = Self::empty();
        let mut space_providers =
            BTreeMap::<u32, (AddressSpaceId, SegmentStorageProviderId)>::new();

        for (space_idx, range) in bounds.iter() {
            let space_id = if space_idx == 0 {
                DEFAULT_SPACE_ID
            } else {
                storage.create_space()
            };

            let provider = S::from_segment_range(range.start, range.end, attributes)?;

            let provider_id = storage.open_provider(provider, SegmentProperties::PERM_ALL);

            space_providers.insert(
                AddressSpaceId::try_from(space_idx)
                    .expect("space index is convertable to a space id"),
                (space_id, provider_id),
            );
        }

        let mut siter = loader.segments();

        while let Some(segm) = siter.next()? {
            let (space_id, provider_id) = space_providers
                .get(&segm.space_index())
                .copied()
                .unwrap_or((DEFAULT_SPACE_ID, DEFAULT_PROVIDER_ID));

            let range = &bounds[segm.space_index() as usize];
            let physical_offset = segm.address().offset().wrapping_sub(range.start.offset());

            tracing::debug!(
                "loading segment {} ({}-{}) at offset {physical_offset:#x} in space {space_id}",
                segm.name(),
                segm.address(),
                segm.next_address()
            );

            storage.write_bytes_direct(provider_id, physical_offset, segm.bytes())?;

            let mapping_id = storage.create_mapping_with_metadata(
                provider_id,
                segm.address(),
                segm.len(),
                physical_offset,
                segm.properties(),
                segm.name().to_owned(),
                segm.mapping_hints().clone(),
                segm.function_hints().clone(),
            )?;
            storage.add_mapping_to_space_top(space_id, mapping_id)?;
        }

        if let Some(project_path) = attributes.get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH) {
            storage.persist_storage(&project_path)?;
        }

        Ok(storage)
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

        let mut provider_map = BTreeMap::new();

        for prov_meta in mem::take(&mut metadata.providers) {
            tracing::debug!(
                "loading segment storage provider `{}` with tag `{}`",
                prov_meta.id,
                prov_meta.stable_tag
            );
            let provider = SegmentStorageProviderRegistry::get().from_storage(
                &prov_meta.stable_tag,
                path,
                attributes,
            )?;
            tracing::debug!(
                "opening segment storage provider `{}` with tag `{}`",
                prov_meta.id,
                prov_meta.stable_tag
            );
            let new_id =
                storage.open_boxed_provider(provider, prov_meta.permissions, prov_meta.stable_tag);
            provider_map.insert(prov_meta.id, new_id);
        }

        let mut space_map = BTreeMap::new();
        space_map.insert(DEFAULT_SPACE_ID, DEFAULT_SPACE_ID);

        for space_meta in &metadata.spaces {
            if space_meta.id != DEFAULT_SPACE_ID {
                let new_id = storage.create_space();
                space_map.insert(space_meta.id, new_id);
            }
        }

        for mapping_meta in &metadata.mappings {
            let provider_id = *provider_map.get(&mapping_meta.provider_id).ok_or_else(|| {
                SegmentStorageError::backing_with(format!(
                    "unknown provider `{}` in metadata",
                    mapping_meta.provider_id
                ))
            })?;
            let space_id = *space_map
                .get(&mapping_meta.space_id)
                .ok_or_else(|| SegmentStorageError::backing_with("unknown space in metadata"))?;

            let mapping_id = storage.create_mapping_with_metadata(
                provider_id,
                Address::from(mapping_meta.virtual_start),
                mapping_meta.size,
                mapping_meta.physical_offset,
                mapping_meta.properties,
                mapping_meta.name.clone(),
                mapping_meta.mapping_hints.clone(),
                mapping_meta.function_hints.clone(),
            )?;

            storage.update_mapping_metadata(mapping_id, mapping_meta.kind, mapping_meta.flags)?;
            storage.add_mapping_to_space_top(space_id, mapping_id)?;
        }

        Ok(storage)
    }

    fn persist_storage(&self, path: impl AsRef<Path>) -> Result<(), SegmentStorageError> {
        let meta_path = path.as_ref().join(SEGMENT_STORAGE_FILE);

        tracing::debug!("persisting segment storage to {}", meta_path.display());

        let providers = self
            .providers
            .values()
            .filter(|p| {
                SegmentStorageProviderRegistry::get()
                    .get_by_tag(p.stable_tag())
                    .is_some_and(|reg| reg.is_persistable())
            })
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
                mapping_ids: b.priority_list().iter().map(|r| r.mapping_id()).collect(),
            })
            .collect::<Vec<_>>();

        let mappings = self
            .mappings
            .values()
            .map(|m| {
                let space_id = self
                    .spaces
                    .iter()
                    .find(|(_, b)| b.priority_list().iter().any(|r| r.mapping_id() == m.id()))
                    .map(|(id, _)| *id)
                    .unwrap_or(DEFAULT_SPACE_ID);

                MappingMetadata {
                    name: m.name().to_owned(),
                    virtual_start: m.start().offset(),
                    physical_offset: m.offset(),
                    size: m.size(),
                    properties: m.properties(),
                    kind: m.kind(),
                    flags: m.flags(),
                    mapping_hints: m.mapping_hints().clone(),
                    function_hints: m.function_hints().clone(),
                    space_id,
                    provider_id: m.provider_id(),
                }
            })
            .collect::<Vec<_>>();

        let metadata = SegmentStorageMetadata {
            providers,
            spaces,
            mappings,
        };

        let file = File::create(&meta_path)
            .map_err(|e| SegmentStorageError::project_data(&meta_path, e.kind()))?;
        let mut writer = BufWriter::new(file);

        bincode::encode_into_std_write(&metadata, &mut writer, bincode::config::standard())
            .map_err(|e| {
                SegmentStorageError::backing_with(format!("failed to encode metadata: {e}"))
            })?;

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

        let metadata = bincode::decode_from_std_read::<SegmentStorageMetadata, _, _>(
            &mut reader,
            bincode::config::standard(),
        )
        .map_err(|e| {
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
        S: PersistableSegmentStorageProvider + 'static,
    {
        let id = self.next_provider_id;
        self.next_provider_id += 1;

        let descriptor = SegmentStorageDescriptor::new(id, provider, permissions);
        self.providers.insert(id, descriptor);

        id
    }

    pub(crate) fn open_boxed_provider(
        &mut self,
        provider: Box<dyn SegmentStorageProvider>,
        permissions: SegmentProperties,
        stable_tag: impl Into<Cow<'static, str>>,
    ) -> SegmentStorageProviderId {
        let id = self.next_provider_id;
        self.next_provider_id += 1;

        let descriptor =
            SegmentStorageDescriptor::from_boxed(id, provider, permissions, stable_tag);
        self.providers.insert(id, descriptor);

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
            .ok_or_else(|| SegmentStorageError::backing_with("provider not found"))?;

        Ok(())
    }

    pub fn create_mapping(
        &mut self,
        provider_id: SegmentStorageProviderId,
        start: impl Into<Address>,
        size: usize,
        offset: u64,
        properties: SegmentProperties,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        if !self.providers.contains_key(&provider_id) {
            return Err(SegmentStorageError::backing_with("provider not found"));
        }

        let id = self.next_mapping_id;
        self.next_mapping_id += 1;

        let mapping = SegmentMapping::new(id, start, size, offset, provider_id, properties);
        self.mappings.insert(id, mapping);

        Ok(id)
    }

    pub fn create_mapping_with_metadata(
        &mut self,
        provider_id: SegmentStorageProviderId,
        start: impl Into<Address>,
        size: usize,
        offset: u64,
        properties: SegmentProperties,
        name: impl Into<String>,
        mapping_hints: std::collections::BTreeMap<Address, crate::lifter::ContextHint>,
        function_hints: std::collections::BTreeSet<Address>,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        if !self.providers.contains_key(&provider_id) {
            return Err(SegmentStorageError::backing_with("provider not found"));
        }

        let id = self.next_mapping_id;
        self.next_mapping_id += 1;

        let mapping = SegmentMapping::new_with_metadata(
            id,
            start,
            size,
            offset,
            provider_id,
            properties,
            name,
            mapping_hints,
            function_hints,
        );
        self.mappings.insert(id, mapping);

        Ok(id)
    }

    pub fn create_mapping_from_builder(
        &mut self,
        builder: SegmentMappingBuilder,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        if !self.providers.contains_key(&builder.provider_id()) {
            return Err(SegmentStorageError::backing_with("provider not found"));
        }

        let id = self.next_mapping_id;
        self.next_mapping_id += 1;

        let mut mapping = SegmentMapping::new_with_metadata(
            id,
            builder.start(),
            builder.size(),
            builder.offset(),
            builder.provider_id(),
            builder.properties(),
            builder.name(),
            builder.mapping_hints().clone(),
            builder.function_hints().clone(),
        );
        mapping.set_kind(builder.kind());
        mapping.set_flags(builder.flags());

        self.mappings.insert(id, mapping);

        Ok(id)
    }

    pub fn remove_mapping(&mut self, id: SegmentMappingId) -> Result<(), SegmentStorageError> {
        for space in self.spaces.values_mut() {
            space.remove_mapping(id);
        }

        self.mappings
            .remove(&id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

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
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        let old_size = mapping.size();
        mapping.set_start(new_start);
        let mapping_ref = mapping.make_ref();

        for space in self.spaces.values_mut() {
            let was_present = space.priority_list().iter().any(|r| r.mapping_id() == id);
            if was_present {
                space.remove_mapping(id);
                space.add_mapping_top(mapping_ref, new_start, old_size, mapping.properties());
            }
        }

        Ok(())
    }

    pub fn resize_mapping(
        &mut self,
        id: SegmentMappingId,
        new_size: usize,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get_mut(&id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        let start = mapping.start();
        mapping.set_size(new_size);
        let mapping_ref = mapping.make_ref();

        for space in self.spaces.values_mut() {
            let was_present = space.priority_list().iter().any(|r| r.mapping_id() == id);
            if was_present {
                space.remove_mapping(id);
                space.add_mapping_top(mapping_ref, start, new_size, mapping.properties());
            }
        }

        Ok(())
    }

    pub fn update_mapping_metadata(
        &mut self,
        id: SegmentMappingId,
        kind: SegmentMappingKind,
        flags: SegmentMappingFlags,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get_mut(&id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        mapping.set_kind(kind);
        mapping.set_flags(flags);

        Ok(())
    }

    pub fn create_space(&mut self) -> AddressSpaceId {
        let id = self.next_space_id;
        self.next_space_id += 1;
        self.spaces.insert(id, AddressSpace::new(id));
        id
    }

    pub fn use_space(&mut self, id: AddressSpaceId) -> Result<(), SegmentStorageError> {
        if !self.spaces.contains_key(&id) {
            return Err(SegmentStorageError::backing_with("space not found"));
        }
        self.current_space = id;
        Ok(())
    }

    pub fn current_space_id(&self) -> AddressSpaceId {
        self.current_space
    }

    pub fn current_space(&self) -> &AddressSpace {
        self.spaces
            .get(&self.current_space)
            .expect("current space should exist")
    }

    pub fn add_mapping_to_space_top(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&mapping_id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        let mapping_ref = mapping.make_ref();
        let start = mapping.start();
        let size = mapping.size();

        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or_else(|| SegmentStorageError::backing_with("space not found"))?;

        space.add_mapping_top(mapping_ref, start, size, mapping.properties());

        Ok(())
    }

    pub fn add_mapping_to_space_bottom(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&mapping_id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        let mapping_ref = mapping.make_ref();
        let start = mapping.start();
        let size = mapping.size();

        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or_else(|| SegmentStorageError::backing_with("space not found"))?;

        space.add_mapping_bottom(mapping_ref, start, size, mapping.properties());

        Ok(())
    }

    pub fn prioritise_mapping(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or_else(|| SegmentStorageError::backing_with("space not found"))?;

        space.prioritise(mapping_id);

        self.rebuild_submaps_for_mapping(space_id, mapping_id)
    }

    pub fn deprioritise_mapping(
        &mut self,
        space_id: AddressSpaceId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let space = self
            .spaces
            .get_mut(&space_id)
            .ok_or_else(|| SegmentStorageError::backing_with("space not found"))?;

        space.deprioritise(mapping_id);

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
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        let range_start = mapping.start();
        let range_end = mapping.end();

        let space = self
            .spaces
            .get(&space_id)
            .ok_or_else(|| SegmentStorageError::backing_with("space not found"))?;

        let overlapping = space
            .priority_list()
            .iter()
            .filter_map(|mref| {
                self.mappings.get(&mref.mapping_id()).and_then(|m| {
                    if m.end() > range_start && m.start() < range_end {
                        Some((*mref, m.start(), m.size(), m.properties()))
                    } else {
                        None
                    }
                })
            })
            .collect::<SmallVec<[_; 8]>>();

        let space = self.spaces.get_mut(&space_id).unwrap();
        space.rebuild_range(range_start, range_end, overlapping);

        Ok(())
    }

    pub fn read_bytes(
        &self,
        addr: impl Into<Address>,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        self.read_bytes_from_space(self.current_space, addr, bytes)
    }

    pub fn read_bytes_from_space(
        &self,
        space_id: AddressSpaceId,
        addr: impl Into<Address>,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        if bytes.is_empty() {
            return Ok(0);
        }

        bytes.fill(self.fill_byte);

        let space = self
            .spaces
            .get(&space_id)
            .ok_or_else(|| SegmentStorageError::backing_with("space not found"))?;

        let addr = addr.into();
        let mut current_addr = addr;
        let mut remaining = bytes.len();
        let mut total_read = 0;

        while remaining > 0 {
            let view = match space.find_containing(current_addr) {
                Some(v) => v,
                None => {
                    current_addr += 1usize;
                    remaining -= 1;
                    continue;
                }
            };

            let mapping_ref = view.mapping_ref();

            let mapping = match self.mappings.get(&mapping_ref.mapping_id()) {
                Some(m) => m,
                None => {
                    current_addr += 1usize;
                    remaining -= 1;
                    continue;
                }
            };

            if !mapping_ref.is_valid(mapping) {
                current_addr += 1usize;
                remaining -= 1;
                continue;
            }

            if !mapping.properties().is_readable() {
                current_addr += 1usize;
                remaining -= 1;
                continue;
            }

            let view_remaining = usize::from(view.end() - current_addr);
            let read_size = remaining.min(view_remaining);

            let phys_offset = mapping.to_offset(current_addr);

            let provider = match self.providers.get(&mapping.provider_id()) {
                Some(p) => p,
                None => {
                    current_addr += read_size;
                    remaining -= read_size;
                    continue;
                }
            };

            let buf_offset = usize::from(current_addr - addr);
            let buf_slice = &mut bytes[buf_offset..buf_offset + read_size];

            provider.provider().read_bytes(phys_offset, buf_slice)?;

            total_read += read_size;
            current_addr += read_size;
            remaining -= read_size;
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
            .ok_or_else(|| SegmentStorageError::backing_with("provider not found"))?;

        provider.provider().read_bytes(offset, bytes)
    }

    pub fn write_bytes(
        &mut self,
        addr: impl Into<Address>,
        bytes: &[u8],
    ) -> Result<usize, SegmentStorageError> {
        self.write_bytes_to_space(self.current_space, addr, bytes)
    }

    pub fn write_bytes_to_space(
        &mut self,
        space_id: AddressSpaceId,
        addr: impl Into<Address>,
        bytes: &[u8],
    ) -> Result<usize, SegmentStorageError> {
        if bytes.is_empty() {
            return Ok(0);
        }

        let mut current_addr = addr.into();
        let mut remaining = bytes.len();
        let mut total_written = 0;
        let mut write_offset = 0;

        while remaining > 0 {
            let view = {
                let space = self
                    .spaces
                    .get(&space_id)
                    .ok_or_else(|| SegmentStorageError::backing_with("space not found"))?;

                match space.find_containing(current_addr) {
                    Some(v) => v,
                    None => {
                        current_addr += 1usize;
                        remaining -= 1;
                        write_offset += 1;
                        continue;
                    }
                }
            };

            let mapping_ref = view.mapping_ref();
            let view_remaining = usize::from(view.end() - current_addr);
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

            provider
                .provider_mut()
                .write_bytes(phys_offset, write_data)?;

            total_written += write_size;
            current_addr += write_size;
            remaining -= write_size;
            write_offset += write_size;
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
            .ok_or_else(|| SegmentStorageError::backing_with("provider not found"))?;

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
        addr: Address,
        bytes: &[u8],
    ) -> Result<(), SegmentStorageError> {
        if self.write_bytes(addr, bytes)? != bytes.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    pub fn set_fill_byte(&mut self, byte: u8) {
        self.fill_byte = byte;
    }

    pub fn fill_byte(&self) -> u8 {
        self.fill_byte
    }

    pub fn resolve_to_offset(
        &self,
        addr: impl Into<Address>,
    ) -> Option<(SegmentStorageProviderId, u64)> {
        let addr = addr.into();
        let space = self.spaces.get(&self.current_space)?;
        let view = space.find_containing(addr)?;
        let mapping = self.mappings.get(&view.mapping_ref().mapping_id())?;
        let offset = mapping.to_offset(addr);
        Some((mapping.provider_id(), offset))
    }

    pub fn contains_segment(&self, at: Address) -> bool {
        if let Some(space) = self.spaces.get(&self.current_space) {
            space.find_containing(at).is_some()
        } else {
            false
        }
    }

    pub fn view_at(
        &self,
        addr: impl Into<Address>,
    ) -> Result<SegmentMappingView<'_>, SegmentStorageError> {
        self.view_of_space_at(self.current_space, addr)
    }

    pub fn view_of_space_at(
        &self,
        space_id: AddressSpaceId,
        addr: impl Into<Address>,
    ) -> Result<SegmentMappingView<'_>, SegmentStorageError> {
        let addr = addr.into();

        let space = self
            .spaces
            .get(&space_id)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let mapping_view = space
            .find_containing(addr)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let mapping = self
            .mappings
            .get(&mapping_view.mapping_ref().mapping_id())
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let provider = self
            .providers
            .get(&mapping.provider_id())
            .ok_or(SegmentStorageError::InvalidAddress)?;

        Ok(SegmentMappingView::new(mapping, provider, mapping_view))
    }

    pub fn iter_views(
        &self,
    ) -> Result<impl Iterator<Item = SegmentMappingView<'_>> + '_, SegmentStorageError> {
        self.iter_views_of_space(self.current_space)
    }

    pub fn iter_views_of_space(
        &self,
        space_id: AddressSpaceId,
    ) -> Result<impl Iterator<Item = SegmentMappingView<'_>> + '_, SegmentStorageError> {
        let space = self
            .spaces
            .get(&space_id)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let views = space.iter().map(|submap| {
            let mapping_ref = submap.mapping_ref();
            let mapping = self
                .mappings
                .get(&mapping_ref.mapping_id())
                .expect("mapping should exist");
            let provider = self
                .providers
                .get(&mapping.provider_id())
                .expect("provider should exist");

            SegmentMappingView::new(mapping, provider, submap)
        });

        Ok(views)
    }
}
