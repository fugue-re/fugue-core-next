use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fugue_core_derive::SegmentStorageProvider;
use memmap2::MmapMut;
use range_set_blaze::RangeSetBlaze;
use rkyv::ser::writer::IoWriter;
use thiserror::Error;

use super::{
    SegmentRangeOverlap, SegmentStorageProvider, SegmentStorageProviderFromSegmentRange,
    SegmentStorageProviderFromStorage, SegmentView,
};
use crate::ir::Address;
use crate::storage::segments::SegmentStorageError;
use crate::storage::{self, PERSISTENT, StoragePersistence, TRANSIENT};
use crate::types::AttributeMap;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;

const PROJECT_MEMORY_MAPPING_DATA: &str = "segment.data.bin";
const PROJECT_MEMORY_MAPPING_META: &str = "segment.data.meta";

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PackExtent {
    offset: u64,
    size: u64,
}

impl PackExtent {
    fn new(offset: u64, size: u64) -> Self {
        Self { offset, size }
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PackMetadata {
    logical_size: u64,
    extents: Vec<PackExtent>,
}

impl PackMetadata {
    fn new(logical_size: u64, extents: Vec<PackExtent>) -> Self {
        Self {
            logical_size,
            extents,
        }
    }
}

struct ExtentPlacement {
    logical: usize,
    source: usize,
    size: usize,
}

impl ExtentPlacement {
    fn new(logical: usize, source: usize, size: usize) -> Self {
        Self {
            logical,
            source,
            size,
        }
    }

    fn relocate(&self, backing: &mut [u8]) {
        if self.logical != self.source {
            backing.copy_within(self.source..self.source + self.size, self.logical);
        }
    }
}

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
    written: RangeSetBlaze<usize>,
    project: PathBuf,
}

#[derive(Debug, Error)]
pub enum MemoryMappedSegmentStorageError {
    #[error("failed to create project: {0}")]
    CreateProject(io::Error),
    #[error("failed to create memory mapping: {0}")]
    CreateMapping(io::Error),
    #[error("failed to flush memory mapping: {0}")]
    FlushMapping(io::Error),
    #[error("failed to pack segment data: {0}")]
    PackSegment(io::Error),
    #[error("failed to unpack segment data: {0}")]
    UnpackSegment(io::Error),
    #[error("failed to encode packed segment metadata: {0}")]
    EncodeMetadata(anyhow::Error),
    #[error("failed to decode packed segment metadata: {0}")]
    DecodeMetadata(anyhow::Error),
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
    pub fn no_project_data(path: impl Into<PathBuf>) -> Self {
        MemoryMappedSegmentStorageError::NoProjectData(path.into())
    }
}

impl From<MemoryMappedSegmentStorageError> for SegmentStorageError {
    fn from(e: MemoryMappedSegmentStorageError) -> Self {
        match e {
            MemoryMappedSegmentStorageError::CreateProject(_)
            | MemoryMappedSegmentStorageError::CreateMapping(_)
            | MemoryMappedSegmentStorageError::FlushMapping(_)
            | MemoryMappedSegmentStorageError::PackSegment(_)
            | MemoryMappedSegmentStorageError::UnpackSegment(_) => SegmentStorageError::backing(e),
            MemoryMappedSegmentStorageError::EncodeMetadata(e)
            | MemoryMappedSegmentStorageError::DecodeMetadata(e) => SegmentStorageError::Backing(e),
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
    pub fn with_size(
        project_path: impl AsRef<Path>,
        size: u64,
    ) -> Result<Self, SegmentStorageError> {
        let project = project_path.as_ref();

        fs::create_dir_all(project).map_err(MemoryMappedSegmentStorageError::CreateProject)?;

        let data_path = project.join(PROJECT_MEMORY_MAPPING_DATA);

        tracing::trace!(
            "creating memory-mapped storage at {} with size {size} bytes",
            data_path.display(),
        );

        let _ = fs::remove_file(project.join(PROJECT_MEMORY_MAPPING_META));

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&data_path)
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;

        file.set_len(size)
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;

        let backing = unsafe { MmapMut::map_mut(&file) }
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;

        Ok(Self {
            backing,
            written: RangeSetBlaze::new(),
            project: project.to_owned(),
        })
    }

    pub fn open_existing(project_path: impl AsRef<Path>) -> Result<Self, SegmentStorageError> {
        let project = project_path.as_ref();
        let data_path = project.join(PROJECT_MEMORY_MAPPING_DATA);
        let meta_path = project.join(PROJECT_MEMORY_MAPPING_META);

        let file = match OpenOptions::new().read(true).write(true).open(&data_path) {
            Ok(file) => file,
            Err(e) => {
                tracing::error!(
                    "memory-mapped storage data file unavailable at {}: {e}",
                    data_path.display()
                );
                return Err(MemoryMappedSegmentStorageError::no_project_data(project).into());
            }
        };

        if meta_path.exists() {
            tracing::trace!("expanding packed segment data at {}", data_path.display());
            return Self::unpack_in_place(project, &meta_path, file);
        }

        tracing::trace!("opening flat backing at {}", data_path.display());

        let file_len = file
            .metadata()
            .map_err(MemoryMappedSegmentStorageError::UnpackSegment)?
            .len();

        let backing = unsafe { MmapMut::map_mut(&file) }
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;

        let mut written = RangeSetBlaze::new();
        if file_len > 0 {
            written.ranges_insert(0..=file_len as usize - 1);
        }

        Ok(Self {
            backing,
            written,
            project: project.to_owned(),
        })
    }

    fn unpack_in_place(
        project: &Path,
        meta_path: &Path,
        file: File,
    ) -> Result<Self, SegmentStorageError> {
        let metadata_bytes =
            fs::read(meta_path).map_err(MemoryMappedSegmentStorageError::UnpackSegment)?;
        let metadata = rkyv::access::<ArchivedPackMetadata, rkyv::rancor::Error>(&metadata_bytes)
            .map_err(|e| {
            MemoryMappedSegmentStorageError::DecodeMetadata(anyhow::Error::new(e))
        })?;

        let logical_size = metadata.logical_size.to_native();

        let mut written = RangeSetBlaze::new();
        let mut placements = Vec::with_capacity(metadata.extents.len());
        let mut compacted = 0usize;
        for extent in metadata.extents.iter() {
            let offset = usize::try_from(extent.offset.to_native()).map_err(|_| {
                SegmentStorageError::backing_with("packed extent offset exceeds usize")
            })?;
            let size = usize::try_from(extent.size.to_native()).map_err(|_| {
                SegmentStorageError::backing_with("packed extent size exceeds usize")
            })?;
            placements.push(ExtentPlacement::new(offset, compacted, size));
            compacted += size;
            if size > 0 {
                written.ranges_insert(offset..=offset + size - 1);
            }
        }

        file.set_len(logical_size)
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
        let mut backing = unsafe { MmapMut::map_mut(&file) }
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;

        for placement in placements.iter().rev() {
            placement.relocate(&mut backing);
        }

        let dirty_end = compacted;
        let mut cursor = 0usize;
        for range in written.ranges() {
            let start = (*range.start()).min(dirty_end);
            if cursor < start {
                backing[cursor..start].fill(0);
            }
            cursor = cursor.max(range.end().saturating_add(1));
            if cursor >= dirty_end {
                break;
            }
        }
        if cursor < dirty_end {
            backing[cursor..dirty_end].fill(0);
        }

        if let Err(e) = fs::remove_file(meta_path) {
            tracing::warn!(
                "failed to remove packed segment metadata at {}: {e}",
                meta_path.display()
            );
        }

        Ok(Self {
            backing,
            written,
            project: project.to_owned(),
        })
    }

    fn pack_in_place(&mut self) -> Result<(), SegmentStorageError> {
        let logical_size = self.backing.len() as u64;

        let mut extents = Vec::new();
        let mut compacted = 0usize;
        for range in self.written.ranges() {
            let offset = *range.start();
            let size = (*range.end() - *range.start()).saturating_add(1);
            if offset != compacted {
                self.backing.copy_within(offset..offset + size, compacted);
            }
            extents.push(PackExtent::new(offset as u64, size as u64));
            compacted += size;
        }

        let metadata = PackMetadata::new(logical_size, extents);

        self.backing
            .flush()
            .map_err(MemoryMappedSegmentStorageError::FlushMapping)?;

        let data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.project.join(PROJECT_MEMORY_MAPPING_DATA))
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
        data_file
            .set_len(compacted as u64)
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
        data_file
            .sync_all()
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;

        let meta_file = File::create(self.project.join(PROJECT_MEMORY_MAPPING_META))
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
        let writer = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(
            &metadata,
            IoWriter::new(meta_file),
        )
        .map_err(|e| MemoryMappedSegmentStorageError::EncodeMetadata(anyhow::Error::new(e)))?;
        writer
            .into_inner()
            .sync_all()
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;

        Ok(())
    }
}

impl<const PERSISTENCE: StoragePersistence> Drop for MemoryMappedSegmentStorage<PERSISTENCE> {
    fn drop(&mut self) {
        if PERSISTENCE == storage::PERSISTENT {
            if let Err(e) = self.pack_in_place() {
                tracing::error!(
                    "failed to pack segment data at {}: {e}",
                    self.project.display()
                );
            }
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
            let existing = Self::open_existing(&project)?;

            if existing.size() != size {
                return Err(SegmentStorageError::backing_with(format!(
                    "existing memory-mapped storage size ({}) does not match expected segment size ({size})",
                    existing.size(),
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
        let offset = usize::try_from(offset).map_err(|_| SegmentStorageError::InvalidAddress)?;
        let available = self.backing.len().saturating_sub(offset);
        let read_size = bytes.len().min(available);

        if read_size == 0 && !bytes.is_empty() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        bytes[..read_size].copy_from_slice(&self.backing[offset..offset + read_size]);
        Ok(read_size)
    }

    fn write_bytes(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, SegmentStorageError> {
        let offset = usize::try_from(offset).map_err(|_| SegmentStorageError::InvalidAddress)?;
        let available = self.backing.len().saturating_sub(offset);
        let write_size = bytes.len().min(available);

        if write_size == 0 && !bytes.is_empty() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        self.backing[offset..offset + write_size].copy_from_slice(&bytes[..write_size]);

        if write_size > 0 {
            self.written.ranges_insert(offset..=offset + write_size - 1);
        }

        Ok(write_size)
    }

    fn view_bytes(&self, offset: u64, n: usize) -> Result<SegmentView<'_>, SegmentStorageError> {
        let size = self.backing.len();
        let offset = usize::try_from(offset).map_err(|_| SegmentStorageError::InvalidAddress)?;
        if offset >= size {
            return Err(SegmentStorageError::InvalidAddress);
        }
        let end = offset
            .checked_add(n)
            .filter(|&end| end <= size)
            .ok_or(SegmentStorageError::InvalidSize)?;

        let mut view = SegmentView::new(n as u64);
        for run in self.written.ranges() {
            let run_start = *run.start();
            if run_start >= end {
                break;
            }
            let run_end = run.end().saturating_add(1);
            if let Some(o) = SegmentRangeOverlap::new(run_start, run_end - run_start, offset, end) {
                let window = o.window();
                view.push(
                    o.window_offset() as u64,
                    &self.backing[offset + window.start..offset + window.end],
                );
            }
        }

        Ok(view)
    }

    fn view_bytes_from(&self, offset: u64) -> Result<SegmentView<'_>, SegmentStorageError> {
        let offset = usize::try_from(offset).map_err(|_| SegmentStorageError::InvalidAddress)?;
        if offset >= self.backing.len() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let mut view = SegmentView::default();
        for run in self.written.ranges() {
            let run_start = *run.start();
            let run_end = run.end().saturating_add(1);
            if run_end <= offset {
                continue;
            }
            if run_start > offset {
                break;
            }
            view.push(0, &self.backing[offset..run_end]);
            view.set_len((run_end - offset) as u64);
            break;
        }

        Ok(view)
    }

    fn size(&self) -> u64 {
        self.backing.len() as u64
    }

    fn flush(&mut self) -> Result<(), SegmentStorageError> {
        self.backing
            .flush()
            .map_err(MemoryMappedSegmentStorageError::FlushMapping)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fugue-memmap-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_pack_roundtrip_sparse() -> Result<(), SegmentStorageError> {
        let dir = scratch("sparse");
        let logical = 0x10_0000u64;

        {
            let mut store = MemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, logical)?;
            store.write_bytes(0x10, b"hello")?;
            store.write_bytes(0x8_0000, b"world")?;
        }

        let data_path = dir.join(PROJECT_MEMORY_MAPPING_DATA);
        let packed_len = fs::metadata(&data_path).unwrap().len();
        assert!(
            packed_len < 0x1000,
            "packed file must be proportional to written bytes, not logical size (got {packed_len})"
        );

        let store = MemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
        assert_eq!(store.size(), logical);

        let mut buf = [0xffu8; 5];
        store.read_bytes(0x10, &mut buf)?;
        assert_eq!(&buf, b"hello");

        let mut buf = [0xffu8; 5];
        store.read_bytes(0x8_0000, &mut buf)?;
        assert_eq!(&buf, b"world");

        let mut gap = [0xffu8; 16];
        store.read_bytes(0x4_0000, &mut gap)?;
        assert!(gap.iter().all(|byte| *byte == 0), "gap must read zero");

        drop(store);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn test_pack_post_load_write() -> Result<(), SegmentStorageError> {
        let dir = scratch("post-load");
        let logical = 0x10_0000u64;

        {
            let mut store = MemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, logical)?;
            store.write_bytes(0x10, b"hello")?;
        }
        {
            let mut store = MemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
            store.write_bytes(0x200, b"patch")?;
        }

        let store = MemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
        let mut buf = [0u8; 5];
        store.read_bytes(0x200, &mut buf)?;
        assert_eq!(&buf, b"patch");
        let mut buf = [0u8; 5];
        store.read_bytes(0x10, &mut buf)?;
        assert_eq!(&buf, b"hello");
        let mut gap = [0xffu8; 8];
        store.read_bytes(0x100, &mut gap)?;
        assert!(gap.iter().all(|byte| *byte == 0));

        drop(store);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn test_pack_fully_initialised() -> Result<(), SegmentStorageError> {
        let dir = scratch("full");
        let payload = (0..0x20u8).collect::<Vec<_>>();

        {
            let mut store = MemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, 0x20)?;
            store.write_bytes(0, &payload)?;
        }

        let store = MemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
        assert_eq!(store.size(), 0x20);
        let mut buf = [0u8; 0x20];
        store.read_bytes(0, &mut buf)?;
        assert_eq!(&buf[..], &payload[..]);

        drop(store);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn test_pack_empty() -> Result<(), SegmentStorageError> {
        let dir = scratch("empty");

        {
            MemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, 0x1000)?;
        }

        let store = MemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
        assert_eq!(store.size(), 0x1000);
        let mut buf = [0xffu8; 32];
        store.read_bytes(0x400, &mut buf)?;
        assert!(buf.iter().all(|byte| *byte == 0));

        drop(store);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
