use std::borrow::Cow;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fugue_core_derive::SegmentStorageProvider;
use memmap2::MmapMut;
use thiserror::Error;

use super::{
    SegmentStorageProvider, SegmentStorageProviderFromSegmentRange,
    SegmentStorageProviderFromStorage,
};
use crate::ir::Address;
use crate::storage::segments::SegmentStorageError;
use crate::storage::{self, PERSISTENT, StoragePersistence, TRANSIENT};
use crate::types::AttributeMap;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;

const PROJECT_MEMORY_MAPPING_DATA: &str = "segment.data.bin";

#[derive(SegmentStorageProvider)]
#[provider(
    concrete = MemoryMappedSegmentStorage<{ PERSISTENT }>,
    tag = "memory-mapped-persistent",
)]
#[provider(
    concrete = MemoryMappedSegmentStorage<{ TRANSIENT }>,
    tag = "memory-mapped-transient",
    persistent = false,
)]
pub struct MemoryMappedSegmentStorage<const PERSISTENCE: StoragePersistence> {
    backing: MmapMut,
    project: PathBuf,
}

#[derive(Debug, Error)]
pub enum MemoryMappedSegmentStorageError {
    #[error("failed to create project: {0}")]
    CreateProject(std::io::Error),
    #[error("failed to create project memory mapping: {0}")]
    CreateProjectMapping(std::io::Error),
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
        MemoryMappedSegmentStorageError::CreateProject(io::Error::other(e.into()))
    }

    pub fn create_project_mapping<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        MemoryMappedSegmentStorageError::CreateProjectMapping(io::Error::other(e.into()))
    }

    pub fn no_project_data(path: impl Into<PathBuf>) -> Self {
        MemoryMappedSegmentStorageError::NoProjectData(path.into())
    }
}

impl From<MemoryMappedSegmentStorageError> for SegmentStorageError {
    fn from(e: MemoryMappedSegmentStorageError) -> Self {
        match e {
            MemoryMappedSegmentStorageError::CreateProject(_)
            | MemoryMappedSegmentStorageError::CreateProjectMapping(_) => {
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

impl<const PERSISTENCE: StoragePersistence> MemoryMappedSegmentStorage<PERSISTENCE> {
    /// Create new flat storage with given size.
    pub fn with_size(
        project_path: impl AsRef<Path>,
        size: u64,
    ) -> Result<Self, SegmentStorageError> {
        let project = project_path.as_ref();

        // Ensure the project directory exists
        fs::create_dir_all(project).map_err(MemoryMappedSegmentStorageError::CreateProject)?;

        let data_path = project.join(PROJECT_MEMORY_MAPPING_DATA);

        tracing::trace!(
            "creating memory-mapped storage at {} with size {} bytes",
            data_path.display(),
            size,
        );

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&data_path)
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        file.set_len(size)
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        let backing = unsafe { MmapMut::map_mut(&file) }
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        Ok(Self {
            backing,
            project: project.to_owned(),
        })
    }

    pub fn open_existing(project_path: impl AsRef<Path>) -> Result<Self, SegmentStorageError> {
        let project = project_path.as_ref();
        let data_path = project.join(PROJECT_MEMORY_MAPPING_DATA);

        if !data_path.exists() {
            tracing::error!(
                "memory-mapped storage data file does not exist at {}",
                data_path.display()
            );
            return Err(MemoryMappedSegmentStorageError::no_project_data(project).into());
        }

        tracing::trace!(
            "opening existing memory-mapped storage at {}",
            data_path.display()
        );

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&data_path)
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        let backing = unsafe { MmapMut::map_mut(&file) }
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;

        Ok(Self {
            backing,
            project: project.to_owned(),
        })
    }
}

impl<const PERSISTENCE: bool> Drop for MemoryMappedSegmentStorage<PERSISTENCE> {
    fn drop(&mut self) {
        if PERSISTENCE == storage::PERSISTENT {
            tracing::trace!("skipping memory-mapped storage clean-up; persistence is enabled");
            return;
        }

        let data_path = self.project.join(PROJECT_MEMORY_MAPPING_DATA);

        if data_path.exists()
            && let Err(e) = fs::remove_file(&data_path)
        {
            tracing::error!(
                "failed to clean-up memory-mapped storage backing at {}: {e}",
                data_path.display()
            );
        }
    }
}

impl SegmentStorageProviderFromStorage for MemoryMappedSegmentStorage<{ PERSISTENT }> {
    fn from_storage(
        path: impl AsRef<Path>,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        Self::open_existing(path)
    }
}

impl<const PERSISTENCE: StoragePersistence> SegmentStorageProviderFromSegmentRange
    for MemoryMappedSegmentStorage<PERSISTENCE>
{
    fn from_segment_range(
        start: Address,
        end: Address,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        let project = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(MemoryMappedSegmentStorageError::NoProjectPath)?;

        let data_path = project.join(PROJECT_MEMORY_MAPPING_DATA);

        let size = end.offset() - start.offset() + 1;

        if data_path.exists() {
            let existing = Self::open_existing(project)?;

            if existing.size() != size {
                return Err(SegmentStorageError::backing_with(format!(
                    "existing memory-mapped storage size ({}) does not match expected segment size ({})",
                    existing.size(),
                    size,
                )));
            }

            return Ok(existing);
        }

        Self::with_size(project, size)
    }
}

impl<const PERSISTENCE: StoragePersistence> SegmentStorageProvider
    for MemoryMappedSegmentStorage<PERSISTENCE>
{
    fn read_bytes(&self, offset: u64, bytes: &mut [u8]) -> Result<usize, SegmentStorageError> {
        let offset = offset as usize;
        let available = self.backing.len().saturating_sub(offset);
        let read_size = bytes.len().min(available);

        if read_size == 0 && !bytes.is_empty() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        bytes[..read_size].copy_from_slice(&self.backing[offset..offset + read_size]);
        Ok(read_size)
    }

    fn write_bytes(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, SegmentStorageError> {
        let offset = offset as usize;
        let available = self.backing.len().saturating_sub(offset);
        let write_size = bytes.len().min(available);

        if write_size == 0 && !bytes.is_empty() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        self.backing[offset..offset + write_size].copy_from_slice(&bytes[..write_size]);
        Ok(write_size)
    }

    fn view_bytes(&self, offset: u64, n: usize) -> Result<Cow<'_, [u8]>, SegmentStorageError> {
        let offset = offset as usize;
        if offset >= self.backing.len() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let end = (offset + n).min(self.backing.len());
        if end - offset < n {
            return Err(SegmentStorageError::InvalidSize);
        }

        Ok(Cow::Borrowed(&self.backing[offset..end]))
    }

    fn view_bytes_from(&self, offset: u64) -> Result<Cow<'_, [u8]>, SegmentStorageError> {
        let offset = offset as usize;
        if offset >= self.backing.len() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        Ok(Cow::Borrowed(&self.backing[offset..]))
    }

    fn size(&self) -> u64 {
        self.backing.len() as u64
    }

    fn flush(&mut self) -> Result<(), SegmentStorageError> {
        self.backing
            .flush()
            .map_err(MemoryMappedSegmentStorageError::CreateProjectMapping)?;
        Ok(())
    }
}
