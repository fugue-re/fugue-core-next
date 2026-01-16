use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::{Address, SegmentProperties};
use crate::loader::{Loadable, LoadableSegment, LoadableSegmentMetadata, LoaderError};
use crate::types::AttributeMap;

pub mod bank;
pub mod mapping;
pub mod memory;
pub mod overlay;
pub mod provider;

pub use bank::{SegmentBank, SegmentBankId};
pub use mapping::{
    SegmentMapping, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind, SegmentMappingRef,
    SegmentMappingView,
};
pub use memory::InMemorySegmentStorage;
pub use overlay::{OverlayChunk, OverlayTree};
pub use provider::{SegmentStorageDescriptor, SegmentStorageProviderId};

pub mod memmap;
pub use memmap::MemoryMappedSegmentStorage;

pub type DefaultPersistentSegmentStorage = MemoryMappedSegmentStorage<{ super::PERSISTENT }>;
pub type DefaultTransientSegmentStorage = InMemorySegmentStorage;

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

pub trait SegmentStorageProviderFromLoadable: SegmentStorageProvider + 'static {
    // Creates a new storage provider from the given loadable object.
    fn from_loadable(
        loader: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError>
    where
        Self: Sized;
}

pub trait SegmentStorageProviderFromStorage: SegmentStorageProviderFromLoadable {
    fn from_storage(
        path: impl AsRef<Path>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError>
    where
        Self: Sized;
}

pub struct SegmentStorageMetadataIter<'a> {
    iter: Box<dyn Iterator<Item = Cow<'a, LoadableSegmentMetadata>> + 'a>,
}

impl SegmentStorageMetadataIter<'_> {
    pub fn new<'a>(
        iter: impl Iterator<Item = Cow<'a, LoadableSegmentMetadata>> + 'a,
    ) -> SegmentStorageMetadataIter<'a> {
        SegmentStorageMetadataIter {
            iter: Box::new(iter),
        }
    }
}

impl<'a> Iterator for SegmentStorageMetadataIter<'a> {
    type Item = Cow<'a, LoadableSegmentMetadata>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

pub trait SegmentStorageProvider {
    // Reads the given bytes from the storage at the specified address; returns the number of bytes
    // read.
    fn read_bytes(&self, addr: Address, bytes: &mut [u8]) -> Result<usize, SegmentStorageError>;

    // Reads the given bytes from the storage at the specified address; fails if not all bytes can
    // be read, e.g., due to gaps or lack of segment coverage.
    fn read_bytes_exact(&self, addr: Address, bytes: &mut [u8]) -> Result<(), SegmentStorageError> {
        if self.read_bytes(addr, bytes)? != bytes.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    // Writes the given bytes to the storage at the specified address; returns the number of bytes
    // written.
    fn write_bytes(&mut self, addr: Address, bytes: &[u8]) -> Result<usize, SegmentStorageError>;

    // Writes the given bytes to the storage at the specified address; fails if not all bytes can
    // be written, e.g., due to gaps or lack of segment coverage.
    fn write_bytes_exact(
        &mut self,
        addr: Address,
        bytes: &[u8],
    ) -> Result<(), SegmentStorageError> {
        if self.write_bytes(addr, bytes)? != bytes.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    // Returns true if the storage has a segment that contains the given address.
    fn contains_segment(&self, at: Address) -> bool;

    // Returns the segment that contains the given address, if any.
    fn find_segment_containing(
        &self,
        addr: Address,
    ) -> Result<Cow<LoadableSegment<'_>>, SegmentStorageError>;

    // Returns a view of length `size` over the bytes of the segment containing the given address.
    fn view_segment_bytes(
        &self,
        addr: Address,
        size: usize,
    ) -> Result<Cow<[u8]>, SegmentStorageError> {
        let addr = addr.into();
        let segm = self.find_segment_containing(addr)?;

        let offset = usize::from(addr - segm.address());
        let bytes = match segm {
            Cow::Borrowed(segm) => Cow::Borrowed(
                segm.view_bytes_at(offset, size)
                    .ok_or(SegmentStorageError::InvalidSize)?,
            ),
            Cow::Owned(segm) => Cow::Owned(
                segm.view_bytes_at(offset, size)
                    .ok_or(SegmentStorageError::InvalidSize)?
                    .to_owned(),
            ),
        };

        Ok(bytes)
    }

    // Returns a view over the bytes of the segment containing the given address, starting from the
    // given address.
    fn view_segment_bytes_from(&self, addr: Address) -> Result<Cow<[u8]>, SegmentStorageError> {
        let addr = addr.into();
        let segm = self.find_segment_containing(addr)?;

        let offset = usize::from(addr - segm.address());
        let bytes = match segm {
            Cow::Borrowed(segm) => Cow::Borrowed(
                segm.view_bytes_from(offset)
                    .ok_or(SegmentStorageError::InvalidSize)?,
            ),
            Cow::Owned(segm) => Cow::Owned(
                segm.view_bytes_from(offset)
                    .ok_or(SegmentStorageError::InvalidSize)?
                    .to_owned(),
            ),
        };

        Ok(bytes)
    }

    // Returns an iterator over the metadata of all segments in the storage.
    fn metadata(&self) -> Result<SegmentStorageMetadataIter<'_>, SegmentStorageError>;

    fn size(&self) -> usize {
        self.metadata()
            .map(|iter| {
                iter.map(|meta| usize::from(meta.address()) + meta.len())
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    // Resizes the backing storage to the given new size.
    fn resize(&mut self, _new_size: u64) -> Result<(), SegmentStorageError> {
        Err(SegmentStorageError::backing_with("resize not supported"))
    }

    // Flushes any pending changes to the backing storage.
    fn flush(&mut self) -> Result<(), SegmentStorageError> {
        Ok(())
    }
}

pub struct SegmentStorage {
    providers: BTreeMap<SegmentStorageProviderId, SegmentStorageDescriptor>,
    mappings: BTreeMap<SegmentMappingId, SegmentMapping>,
    banks: BTreeMap<SegmentBankId, SegmentBank>,

    current_bank: SegmentBankId,
    overlay_enabled: bool,
    fill_byte: u8,

    next_provider_id: u32,
    next_mapping_id: u32,
    next_bank_id: u32,

    default_bank_id: SegmentBankId,
}

impl SegmentStorage {
    pub fn empty() -> Self {
        let default_bank_id = 0;
        let mut banks = BTreeMap::new();
        banks.insert(default_bank_id, SegmentBank::new(default_bank_id));

        Self {
            providers: BTreeMap::new(),
            mappings: BTreeMap::new(),
            banks,
            current_bank: default_bank_id,
            overlay_enabled: false,
            fill_byte: 0,
            next_provider_id: 0,
            next_mapping_id: 0,
            next_bank_id: 1,
            default_bank_id,
        }
    }

    pub fn new(
        backing: impl SegmentStorageProvider + 'static,
    ) -> Result<Self, SegmentStorageError> {
        let mut storage = Self::empty();

        let segments = backing
            .metadata()
            .map(|iter| {
                iter.map(|meta| (meta.address(), meta.len(), meta.properties()))
                    .collect::<SmallVec<[_; 8]>>()
            })
            .unwrap_or_default();

        let provider_id = storage.open_provider(backing, SegmentProperties::PERM_ALL);
        let default_bank_id = storage.default_bank_id;

        for (addr, size, props) in segments {
            // For identity mapping (virtual == physical), delta should equal the base address
            // so that to_offset() returns: (virt - virt_start) + delta = (virt - start) + start = virt
            let delta = addr.offset() as i64;
            let mapping_id = storage.create_mapping(provider_id, addr, size, delta, props)?;
            storage.add_mapping_to_bank_top(default_bank_id, mapping_id)?;
        }

        Ok(storage)
    }

    pub fn open_provider(
        &mut self,
        provider: impl SegmentStorageProvider + 'static,
        permissions: SegmentProperties,
    ) -> SegmentStorageProviderId {
        let id = self.next_provider_id;
        self.next_provider_id += 1;

        let descriptor = SegmentStorageDescriptor::new(id, provider, permissions);
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
        delta: i64,
        properties: SegmentProperties,
    ) -> Result<SegmentMappingId, SegmentStorageError> {
        if !self.providers.contains_key(&provider_id) {
            return Err(SegmentStorageError::backing_with("provider not found"));
        }

        let id = self.next_mapping_id;
        self.next_mapping_id += 1;

        let mapping = SegmentMapping::new(id, start, size, delta, provider_id, properties);
        self.mappings.insert(id, mapping);

        Ok(id)
    }

    pub fn remove_mapping(&mut self, id: SegmentMappingId) -> Result<(), SegmentStorageError> {
        for bank in self.banks.values_mut() {
            bank.remove_mapping(id);
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

        for bank in self.banks.values_mut() {
            let was_present = bank.priority_list().iter().any(|r| r.mapping_id() == id);
            if was_present {
                bank.remove_mapping(id);
                bank.add_mapping_top(mapping_ref, new_start, old_size);
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

        for bank in self.banks.values_mut() {
            let was_present = bank.priority_list().iter().any(|r| r.mapping_id() == id);
            if was_present {
                bank.remove_mapping(id);
                bank.add_mapping_top(mapping_ref, start, new_size);
            }
        }

        Ok(())
    }

    pub fn set_mapping_metadata(
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

    pub fn create_bank(&mut self) -> SegmentBankId {
        let id = self.next_bank_id;
        self.next_bank_id += 1;
        self.banks.insert(id, SegmentBank::new(id));
        id
    }

    pub fn use_bank(&mut self, id: SegmentBankId) -> Result<(), SegmentStorageError> {
        if !self.banks.contains_key(&id) {
            return Err(SegmentStorageError::backing_with("bank not found"));
        }
        self.current_bank = id;
        Ok(())
    }

    pub fn current_bank_id(&self) -> SegmentBankId {
        self.current_bank
    }

    pub fn default_bank_id(&self) -> SegmentBankId {
        self.default_bank_id
    }

    pub fn add_mapping_to_bank_top(
        &mut self,
        bank_id: SegmentBankId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&mapping_id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        let mapping_ref = mapping.make_ref();
        let start = mapping.start();
        let size = mapping.size();

        let bank = self
            .banks
            .get_mut(&bank_id)
            .ok_or_else(|| SegmentStorageError::backing_with("bank not found"))?;

        bank.add_mapping_top(mapping_ref, start, size);

        Ok(())
    }

    pub fn add_mapping_to_bank_bottom(
        &mut self,
        bank_id: SegmentBankId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&mapping_id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        let mapping_ref = mapping.make_ref();
        let start = mapping.start();
        let size = mapping.size();

        let bank = self
            .banks
            .get_mut(&bank_id)
            .ok_or_else(|| SegmentStorageError::backing_with("bank not found"))?;

        bank.add_mapping_bottom(mapping_ref, start, size);

        Ok(())
    }

    pub fn prioritise_mapping(
        &mut self,
        bank_id: SegmentBankId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let bank = self
            .banks
            .get_mut(&bank_id)
            .ok_or_else(|| SegmentStorageError::backing_with("bank not found"))?;

        bank.prioritise(mapping_id);
        Ok(())
    }

    pub fn deprioritise_mapping(
        &mut self,
        bank_id: SegmentBankId,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let bank = self
            .banks
            .get_mut(&bank_id)
            .ok_or_else(|| SegmentStorageError::backing_with("bank not found"))?;

        bank.deprioritise(mapping_id);
        Ok(())
    }

    pub fn read_bytes(
        &self,
        addr: Address,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        self.read_bytes_from_bank(self.current_bank, addr, bytes)
    }

    pub fn read_bytes_from_bank(
        &self,
        bank_id: SegmentBankId,
        addr: Address,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        if bytes.is_empty() {
            return Ok(0);
        }

        bytes.fill(self.fill_byte);

        let bank = self
            .banks
            .get(&bank_id)
            .ok_or_else(|| SegmentStorageError::backing_with("bank not found"))?;

        let mut current_addr = addr;
        let mut remaining = bytes.len();
        let mut total_read = 0;

        while remaining > 0 {
            let view = match bank.find_containing(current_addr) {
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

            provider
                .provider()
                .read_bytes(phys_offset.into(), buf_slice)?;

            if self.overlay_enabled {
                mapping.overlay().read(current_addr, buf_slice);
            }

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

        provider.provider().read_bytes(offset.into(), bytes)
    }

    pub fn write_bytes(
        &mut self,
        addr: Address,
        bytes: &[u8],
    ) -> Result<usize, SegmentStorageError> {
        self.write_bytes_to_bank(self.current_bank, addr, bytes)
    }

    pub fn write_bytes_to_bank(
        &mut self,
        bank_id: SegmentBankId,
        addr: Address,
        bytes: &[u8],
    ) -> Result<usize, SegmentStorageError> {
        if bytes.is_empty() {
            return Ok(0);
        }

        let mut current_addr = addr;
        let mut remaining = bytes.len();
        let mut total_written = 0;
        let mut write_offset = 0;

        while remaining > 0 {
            let view = {
                let bank = self
                    .banks
                    .get(&bank_id)
                    .ok_or_else(|| SegmentStorageError::backing_with("bank not found"))?;

                match bank.find_containing(current_addr) {
                    Some(v) => v.clone(),
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

            if self.overlay_enabled {
                mapping
                    .overlay_mut()
                    .write(current_addr, write_data.to_vec());
            } else {
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
                    .write_bytes(phys_offset.into(), write_data)?;
            }

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

        provider.provider_mut().write_bytes(offset.into(), bytes)
    }

    pub fn read_bytes_exact(
        &self,
        addr: Address,
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

    pub fn enable_overlay(&mut self, enabled: bool) {
        self.overlay_enabled = enabled;
    }

    pub fn is_overlay_enabled(&self) -> bool {
        self.overlay_enabled
    }

    pub fn commit_overlay(
        &mut self,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get(&mapping_id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        let provider_id = mapping.provider_id();
        let overlay_data: Vec<_> = mapping.overlay().iter().collect();

        let provider = self
            .providers
            .get_mut(&provider_id)
            .ok_or_else(|| SegmentStorageError::backing_with("provider not found"))?;

        for (addr, chunk) in overlay_data {
            let mapping = self.mappings.get(&mapping_id).unwrap();
            let phys_offset = mapping.to_offset(addr);
            provider
                .provider_mut()
                .write_bytes(phys_offset.into(), chunk.data())?;
        }

        Ok(())
    }

    pub fn clear_overlay(
        &mut self,
        mapping_id: SegmentMappingId,
    ) -> Result<(), SegmentStorageError> {
        let mapping = self
            .mappings
            .get_mut(&mapping_id)
            .ok_or_else(|| SegmentStorageError::backing_with("mapping not found"))?;

        mapping.overlay_mut().clear();
        Ok(())
    }

    pub fn set_fill_byte(&mut self, byte: u8) {
        self.fill_byte = byte;
    }

    pub fn fill_byte(&self) -> u8 {
        self.fill_byte
    }

    pub fn resolve_to_offset(&self, addr: Address) -> Option<(SegmentStorageProviderId, u64)> {
        let bank = self.banks.get(&self.current_bank)?;
        let view = bank.find_containing(addr)?;
        let mapping = self.mappings.get(&view.mapping_ref().mapping_id())?;
        let offset = mapping.to_offset(addr);
        Some((mapping.provider_id(), offset))
    }

    pub fn list_providers(&self) -> Vec<SegmentStorageProviderId> {
        self.providers.keys().copied().collect()
    }

    pub fn list_mappings(&self) -> Vec<SegmentMappingId> {
        self.mappings.keys().copied().collect()
    }

    pub fn list_banks(&self) -> Vec<SegmentBankId> {
        self.banks.keys().copied().collect()
    }

    pub fn contains_segment(&self, at: Address) -> bool {
        if let Some(bank) = self.banks.get(&self.current_bank) {
            bank.find_containing(at).is_some()
        } else {
            false
        }
    }

    pub fn find_segment_containing<'a>(
        &'a self,
        addr: Address,
    ) -> Result<Cow<'a, LoadableSegment<'a>>, SegmentStorageError> {
        let bank = self
            .banks
            .get(&self.current_bank)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let view = bank
            .find_containing(addr)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let mapping = self
            .mappings
            .get(&view.mapping_ref().mapping_id())
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let provider = self
            .providers
            .get(&mapping.provider_id())
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let phys_addr = mapping.to_offset(addr);
        provider
            .provider()
            .find_segment_containing(phys_addr.into())
    }

    pub fn view_segment_bytes(
        &self,
        addr: Address,
        size: usize,
    ) -> Result<Cow<[u8]>, SegmentStorageError> {
        let segm = self.find_segment_containing(addr)?;

        let offset = usize::from(addr - segm.address());
        let bytes = match &segm {
            Cow::Borrowed(s) => s.view_bytes_at(offset, size),
            Cow::Owned(s) => s.view_bytes_at(offset, size),
        }
        .ok_or(SegmentStorageError::InvalidSize)?
        .to_owned();

        Ok(Cow::Owned(bytes))
    }

    pub fn view_segment_bytes_from<'a>(
        &'a self,
        addr: Address,
    ) -> Result<Cow<'a, [u8]>, SegmentStorageError> {
        let segm = self.find_segment_containing(addr)?;

        let offset = usize::from(addr - segm.address());
        match segm {
            Cow::Borrowed(s) => s.view_bytes_from(offset).map(Cow::Borrowed),
            Cow::Owned(s) => s.view_bytes_from(offset).map(|b| Cow::Owned(b.to_owned())),
        }
        .ok_or(SegmentStorageError::InvalidSize)
    }

    pub fn metadata(&self) -> Result<SegmentStorageMetadataIter<'_>, SegmentStorageError> {
        let mut all_metadata = Vec::<Cow<'_, LoadableSegmentMetadata>>::new();

        for provider in self.providers.values() {
            if let Ok(iter) = provider.provider().metadata() {
                for meta in iter {
                    all_metadata.push(meta);
                }
            }
        }

        Ok(SegmentStorageMetadataIter::new(all_metadata.into_iter()))
    }
}

impl Default for SegmentStorage {
    fn default() -> Self {
        Self::empty()
    }
}
