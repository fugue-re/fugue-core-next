use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader};
use std::ops::Range;
use std::path::{Path, PathBuf};

use bincode::{Decode, Encode};
use fallible_iterator::FallibleIterator;
use hex_display::HexDisplayExt;
use memmap2::MmapMut;
use thiserror::Error;

use crate::ir::{Address, SegmentProperties};
use crate::loader::{Loadable, LoadableSegment, Loader};
use crate::storage::{self, PERSISTENT, StoragePersistence};
use crate::types::AttributeMap;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;

use super::{
    SegmentStorageError, SegmentStorageProvider, SegmentStorageProviderFromLoadable,
    SegmentStorageProviderFromStorage,
};

const PROJECT_MEMORY_MAPPING_DATA: &str = "segment.data.bin";
const PROJECT_MEMORY_MAPPING_META: &str = "segment.meta.bin";

pub struct MemoryMappedSegmentStorage<const PERSISTENCE: StoragePersistence> {
    backing: MmapMut,
    segments: Vec<LoadableSegmentMetadata>,
    project: PathBuf,
}

#[derive(Debug, Error)]
pub enum MemoryMappedSegmentStorageError {
    #[error("failed to create project: {0}")]
    CreateProject(std::io::Error),
    #[error("failed to create project memory mapping: {0}")]
    CreateProjectMapping(std::io::Error),
    #[error("failed to create project memory mapping metadata: {0}")]
    CreateProjectMetadata(std::io::Error),
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid size")]
    InvalidSize,
    #[error("no project path specified")]
    NoProjectPath,
    #[error("failed to read project data from `{0}`")]
    NoProjectData(PathBuf),
}

impl MemoryMappedSegmentStorageError {
    pub fn create_project<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        MemoryMappedSegmentStorageError::CreateProject(io::Error::new(
            io::ErrorKind::Other,
            e.into(),
        ))
    }

    pub fn create_project_mapping<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        MemoryMappedSegmentStorageError::CreateProjectMapping(io::Error::new(
            io::ErrorKind::Other,
            e.into(),
        ))
    }

    pub fn create_project_metadata<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        MemoryMappedSegmentStorageError::CreateProjectMetadata(io::Error::new(
            io::ErrorKind::Other,
            e.into(),
        ))
    }

    pub fn no_project_data(path: impl Into<PathBuf>) -> Self {
        MemoryMappedSegmentStorageError::NoProjectData(path.into())
    }
}

impl From<MemoryMappedSegmentStorageError> for SegmentStorageError {
    fn from(e: MemoryMappedSegmentStorageError) -> Self {
        match e {
            MemoryMappedSegmentStorageError::CreateProject(_)
            | MemoryMappedSegmentStorageError::CreateProjectMapping(_)
            | MemoryMappedSegmentStorageError::CreateProjectMetadata(_) => {
                SegmentStorageError::backing(e)
            }
            MemoryMappedSegmentStorageError::InvalidAddress => SegmentStorageError::InvalidAddress,
            MemoryMappedSegmentStorageError::InvalidSize => SegmentStorageError::InvalidSize,
            MemoryMappedSegmentStorageError::NoProjectPath => SegmentStorageError::InvalidAddress,
            MemoryMappedSegmentStorageError::NoProjectData(path) => {
                SegmentStorageError::ProjectData(path, io::ErrorKind::NotFound)
            }
        }
    }
}

#[derive(Encode, Decode)]
pub struct MemoryMappedSegmentStorageMetadata {
    digest: [u8; 32],                       // Digest provided by the loader metadata
    segments: Vec<LoadableSegmentMetadata>, // Segment metadataa sorted by address
}

impl MemoryMappedSegmentStorageMetadata {
    pub fn expected_size(&self) -> usize {
        self.segments
            .iter()
            .map(|segm| segm.physical_offset + segm.size)
            .max()
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct LoadableSegmentMetadata {
    name: String,
    address: Address,
    physical_offset: usize,
    properties: SegmentProperties,
    size: usize,
    function_hints: BTreeSet<Address>,
}

impl LoadableSegmentMetadata {
    pub fn new(segm: &LoadableSegment, physical_offset: usize) -> Self {
        Self {
            address: segm.address(),
            name: segm.name().to_owned(),
            physical_offset,
            properties: segm.properties(),
            size: segm.len(),
            function_hints: segm.function_hints().clone(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn last_address(&self) -> Address {
        self.address + self.size as u64 - 1usize
    }

    pub fn next_address(&self) -> Address {
        self.address + self.size
    }

    pub fn physical_offset(&self) -> usize {
        self.physical_offset
    }

    pub fn physical_range(&self) -> Range<usize> {
        self.physical_offset..self.physical_offset + self.size
    }

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }

    pub fn function_hints(&self) -> &BTreeSet<Address> {
        &self.function_hints
    }

    pub fn len(&self) -> usize {
        self.size
    }
}

impl<const PERSISTENCE: StoragePersistence> MemoryMappedSegmentStorage<PERSISTENCE> {
    fn from_existing(
        project: impl AsRef<Path>,
        meta: impl AsRef<Path>,
        segments: impl AsRef<Path>,
        loader: Option<&impl Loadable>,
    ) -> Result<Self, SegmentStorageError> {
        let project = project.as_ref();
        let meta = meta.as_ref();
        let segments = segments.as_ref();

        tracing::trace!(
            "loading (existing) memory-mapped storage for project {}",
            project.display(),
        );

        tracing::trace!(
            "loading memory-mapped storage metadata from {}",
            meta.display()
        );

        let mut meta_file = BufReader::new(
            File::open(&meta).map_err(MemoryMappedSegmentStorageError::CreateProjectMetadata)?,
        );

        let metadata = bincode::decode_from_std_read::<MemoryMappedSegmentStorageMetadata, _, _>(
            &mut meta_file,
            bincode::config::standard(),
        )
        .map_err(MemoryMappedSegmentStorageError::create_project_metadata)?;

        tracing::trace!(
            "loading memory-mapped storage backing from {}",
            segments.display()
        );

        if let Some(loader) = loader
            && metadata.digest != loader.metadata().digest()
        {
            tracing::error!(
                "memory-mapped storage loader digest mismatch: expected {}, got {}",
                metadata.digest.hex(),
                loader.metadata().digest().hex(),
            );
            return Err(
                MemoryMappedSegmentStorageError::create_project("corrupted storage").into(),
            );
        }

        let backing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&segments)
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        let backing = unsafe { MmapMut::map_mut(&backing_file) }
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        // perform a quick sanity check on the backing size
        let backing_size = backing.len();
        let expected_size = metadata.expected_size();

        if backing_size != expected_size {
            tracing::error!(
                "memory-mapped storage backing size mismatch: expected {expected_size} bytes, got {backing_size} bytes",
            );
            return Err(
                MemoryMappedSegmentStorageError::create_project("corrupted storage").into(),
            );
        }

        Ok(Self {
            backing,
            segments: metadata.segments,
            project: project.to_owned(),
        })
    }

    fn from_loadable_aux(
        project: impl AsRef<Path>,
        loader: &impl Loadable,
    ) -> Result<Self, SegmentStorageError> {
        // Ensure the project directory exists
        let project = project.as_ref();
        fs::create_dir_all(&project).map_err(MemoryMappedSegmentStorageError::CreateProject)?;

        let path = project.join(PROJECT_MEMORY_MAPPING_DATA);

        tracing::trace!(
            "creating memory-mapped storage for project {} at {}",
            project.display(),
            path.display(),
        );

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        let (start, end) = loader.segment_range();
        let size = usize::from(end - start) + 1usize;

        tracing::trace!("memory-mapped storage size is {size} bytes");

        file.set_len(size as _)
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        let mut siter = loader.segments();

        let mut backing = unsafe { MmapMut::map_mut(&file) }
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        let mut segments = Vec::new();

        while let Some(segm) = siter.next()? {
            let offset = usize::from(segm.address() - start);

            tracing::trace!(
                "loading segment {} ({}-{}) into memory-mapped storage at offset {offset:#x}",
                segm.name(),
                segm.address(),
                segm.next_address()
            );

            segments.push(LoadableSegmentMetadata::new(&segm, offset));

            backing[offset..offset + segm.len()].copy_from_slice(segm.bytes());
        }

        segments.sort_by(|a, b| a.address().cmp(&b.address()));

        let segments = if PERSISTENCE == storage::PERSISTENT {
            let meta = project.join(PROJECT_MEMORY_MAPPING_META);

            tracing::trace!(
                "writing memory-mapped storage metadata to {}",
                meta.display()
            );

            let mut file = File::create(&meta)
                .map_err(MemoryMappedSegmentStorageError::CreateProjectMetadata)?;

            let metadata = MemoryMappedSegmentStorageMetadata {
                digest: loader.metadata().digest(),
                segments,
            };

            bincode::encode_into_std_write(&metadata, &mut file, bincode::config::standard())
                .map_err(MemoryMappedSegmentStorageError::create_project_metadata)?;

            metadata.segments
        } else {
            tracing::trace!("not writing memory-mapped storage metadata (non-persistent)");
            segments
        };

        Ok(Self {
            backing,
            segments,
            project: project.to_owned(),
        })
    }

    fn position(&self, addr: Address) -> Option<usize> {
        self.segments
            .binary_search_by(|segm| {
                if addr < segm.address() {
                    std::cmp::Ordering::Greater
                } else if addr > segm.last_address() {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
    }

    fn overlapping(
        &self,
        addr: Address,
        size: usize,
    ) -> Option<impl Iterator<Item = &LoadableSegmentMetadata>> {
        let last_addr = addr + size;

        if last_addr < addr {
            return None;
        }

        let first = self.position(addr)?;
        let last = self
            .position(last_addr)
            .unwrap_or_else(|| self.segments.len() - 1);

        let view = &self.segments[first..last + 1];

        for i in 0..view.len() - 1usize {
            if view[i].next_address() != view[i + 1].address() {
                return Some(view[..=i].iter());
            }
        }

        Some(view.iter())
    }
}

impl<const PERSISTENCE: bool> Drop for MemoryMappedSegmentStorage<PERSISTENCE> {
    fn drop(&mut self) {
        if PERSISTENCE == storage::PERSISTENT {
            tracing::trace!("skipping memory-mapped storage clean-up; persistence is enabled",);
            return;
        }

        let meta = self.project.join(PROJECT_MEMORY_MAPPING_META);
        if meta.exists()
            && let Err(e) = fs::remove_file(&meta)
        {
            tracing::error!(
                "failed to clean-up memory-mapped storage metadata at {}: {e}",
                meta.display()
            );
        }

        let segments = self.project.join(PROJECT_MEMORY_MAPPING_DATA);
        if segments.exists()
            && let Err(e) = fs::remove_file(&segments)
        {
            tracing::error!(
                "failed to clean-up memory-mapped storage backing at {}: {e}",
                segments.display()
            );
        }
    }
}

impl SegmentStorageProviderFromStorage for MemoryMappedSegmentStorage<{ PERSISTENT }> {
    fn from_storage(
        path: impl AsRef<Path>,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        let project = path.as_ref();
        let meta = project.join(PROJECT_MEMORY_MAPPING_META);
        let segments = project.join(PROJECT_MEMORY_MAPPING_DATA);

        if !meta.exists() || !segments.exists() {
            tracing::error!(
                "memory-mapped storage for project {} does not exist at {}; cannot load",
                project.display(),
                segments.display()
            );
            return Err(MemoryMappedSegmentStorageError::no_project_data(project).into());
        }

        tracing::trace!(
            "loading memory-mapped storage for project {} from {}",
            project.display(),
            segments.display()
        );

        Self::from_existing(&project, &meta, &segments, None::<&Loader>)
            .map_err(SegmentStorageError::from)
    }
}

impl<const PERSISTENCE: StoragePersistence> SegmentStorageProviderFromLoadable
    for MemoryMappedSegmentStorage<PERSISTENCE>
{
    fn from_loadable(
        loader: &impl Loadable,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        let project = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(MemoryMappedSegmentStorageError::NoProjectPath)?;

        let meta = project.join(PROJECT_MEMORY_MAPPING_META);
        let segments = project.join(PROJECT_MEMORY_MAPPING_DATA);

        let result = if meta.exists() && segments.exists() {
            tracing::trace!(
                "memory-mapped storage for project {} already exists at {}; reusing",
                project.display(),
                segments.display()
            );

            Self::from_existing(&project, &meta, &segments, Some(loader))
        } else {
            tracing::trace!(
                "memory-mapped storage for project {} does not exist at {}; creating",
                project.display(),
                segments.display()
            );

            Self::from_loadable_aux(&project, loader)
        };

        if result.is_err() {
            tracing::error!("failed to create memory-mapped storage; cleaning-up");
            if PERSISTENCE == storage::PERSISTENT {
                // NOTE: metadata is only created if persistence is enabled
                fs::remove_file(&meta).ok();
            }
            fs::remove_file(&segments).ok();
        }

        result
    }
}

impl<const PERSISTENCE: StoragePersistence> SegmentStorageProvider
    for MemoryMappedSegmentStorage<PERSISTENCE>
{
    fn read_bytes(&self, addr: Address, bytes: &mut [u8]) -> Result<usize, SegmentStorageError> {
        let mut size = bytes.len();
        let mut offset = 0;

        tracing::trace!("reading {size} bytes from address {addr}");

        if bytes.is_empty() {
            return Ok(offset);
        }

        let segms = self
            .overlapping(addr, size)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        for segm in segms {
            let read_addr = addr + offset;

            let segm_addr = segm.address();
            let segm_last_addr = segm.last_address();

            let read_offset = segm.physical_offset() + usize::from(read_addr - segm_addr);
            let read_size = size.min(usize::from(segm_last_addr - read_addr) + 1);

            let segm_bytes = self
                .backing
                .get(read_offset..read_offset + read_size)
                .ok_or(SegmentStorageError::InvalidAddress)?;

            bytes[offset..offset + read_size].copy_from_slice(segm_bytes);

            size -= read_size;
            offset += read_size;

            if size == 0 {
                break;
            }
        }

        Ok(offset)
    }

    fn write_bytes(&mut self, addr: Address, bytes: &[u8]) -> Result<usize, SegmentStorageError> {
        let mut size = bytes.len();
        let mut offset = 0;

        tracing::trace!("writing {size} bytes to address {addr}");

        if bytes.is_empty() {
            return Ok(offset);
        }

        let last_addr = addr + size;

        if last_addr < addr {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let first = self
            .position(addr)
            .ok_or(SegmentStorageError::InvalidAddress)?;
        let last = self
            .position(last_addr)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        let segms = &self.segments[first..last + 1];

        for i in 0..segms.len() - 1usize {
            if segms[i].next_address() != segms[i + 1].address() {
                return Err(SegmentStorageError::InvalidAddress);
            }
        }

        for segm in segms.iter() {
            let write_addr = addr + offset;

            let segm_addr = segm.address();
            let segm_last_addr = segm.last_address();

            let write_offset = segm.physical_offset() + usize::from(write_addr - segm_addr);
            let write_size = size.min(usize::from(segm_last_addr - write_addr) + 1);

            let segm_bytes = self
                .backing
                .get_mut(write_offset..write_offset + write_size)
                .ok_or(SegmentStorageError::InvalidAddress)?;

            segm_bytes.copy_from_slice(&bytes[offset..offset + write_size]);

            size -= write_size;
            offset += write_size;

            if size == 0 {
                break;
            }
        }

        Ok(offset)
    }

    fn contains_segment(&self, addr: Address) -> bool {
        self.position(addr).is_some()
    }

    fn find_segment_containing(
        &self,
        addr: Address,
    ) -> Result<Cow<LoadableSegment<'_>>, SegmentStorageError> {
        self.position(addr)
            .map(|pos| {
                let segm = &self.segments[pos];
                let bytes = Cow::Borrowed(&self.backing[segm.physical_range()]);
                Cow::Owned(LoadableSegment::from_parts(
                    segm.name(),
                    segm.address(),
                    segm.properties(),
                    bytes,
                    Cow::Borrowed(segm.function_hints()),
                ))
            })
            .ok_or(SegmentStorageError::InvalidAddress)
    }
}
