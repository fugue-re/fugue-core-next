use std::error::Error as StdError;
use std::fs::{self, File};
use std::hint::cold_path;
use std::io::{self, Write};
use std::ops::{Range, RangeInclusive};
use std::path::{Path, PathBuf};

use fugue_core_derive::SegmentStorageProvider;
use memmap2::{Mmap, MmapMut};
use range_set_blaze::RangeSetBlaze;
#[allow(deprecated)]
use range_set_blaze::Rog;
use tempfile::tempfile_in;
use thiserror::Error;

use super::{
    SegmentStorageProvider, SegmentStorageProviderFromSegmentRange,
    SegmentStorageProviderFromStorage, SegmentStorageProviderId, SegmentView,
};
use crate::ir::{Address, AddressRangeExt};
use crate::storage::segments::SegmentStorageError;
use crate::storage::{self, PERSISTENT, StoragePersistence, TRANSIENT};
use crate::types::AttributeMap;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;

pub(crate) mod packed;

const MAX_BACKING_GAP: u64 = 4 * 1024 * 1024;

const PROJECT_MEMORY_MAPPING_DATA: &str = "segment.data.bin";
const PROJECT_MEMORY_MAPPING_META: &str = "segment.data.meta";

#[derive(Default)]
struct WrittenExtents {
    ranges: RangeSetBlaze<u64>,
}

impl WrittenExtents {
    fn iter(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.ranges
            .ranges()
            .map(|range| *range.start()..range.end().saturating_add(1))
    }

    #[allow(deprecated)]
    fn run_at(&self, offset: u64) -> Option<Range<u64>> {
        match self.ranges.rogs_get(offset) {
            Rog::Range(range) => Some(*range.start()..range.end().saturating_add(1)),
            Rog::Gap(_) => None,
        }
    }

    #[allow(deprecated)]
    fn runs_in(&self, range: Range<u64>) -> impl Iterator<Item = Range<u64>> + '_ {
        let rogs = (!range.is_empty()).then(|| self.ranges.rogs_range(range.start..=range.end - 1));

        rogs.into_iter().flatten().filter_map(|rog| match rog {
            Rog::Range(range) => Some(*range.start()..range.end().saturating_add(1)),
            Rog::Gap(_) => None,
        })
    }

    fn insert(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }

        self.ranges.ranges_insert(range.start..=range.end - 1);
    }
}

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

struct MappedBacking {
    base: u64,
    end: u64,
    file: File,
    mapping: MmapMut,
}

impl MappedBacking {
    fn new(project: &Path, base: u64, size: u64) -> Result<Self, SegmentStorageError> {
        let file = tempfile_in(project).map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
        file.set_len(size)
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
        let mapping = unsafe { MmapMut::map_mut(&file) }
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
        Ok(Self {
            base,
            end: base + size,
            file,
            mapping,
        })
    }

    fn resize(&mut self, size: u64) -> Result<(), SegmentStorageError> {
        self.file
            .set_len(size)
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
        self.mapping = unsafe { MmapMut::map_mut(&self.file) }
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
        Ok(())
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
    backing: Vec<MappedBacking>,
    size: u64,
    written: WrittenExtents,
    project: PathBuf,
}

#[derive(Debug, Error)]
pub enum MemoryMappedSegmentStorageError {
    #[error("failed to create memory mapping: {0}")]
    CreateMapping(io::Error),
    #[error("failed to create project: {0}")]
    CreateProject(io::Error),
    #[error("failed to decode packed segment metadata: {0}")]
    DecodeMetadata(anyhow::Error),
    #[error("failed to encode packed segment metadata: {0}")]
    EncodeMetadata(anyhow::Error),
    #[error("failed to flush memory mapping: {0}")]
    FlushMapping(io::Error),
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid size")]
    InvalidSize,
    #[error("failed to read project data from `{0}`")]
    NoProjectData(PathBuf),
    #[error("no project path specified")]
    NoProjectPath,
    #[error("failed to pack segment data: {0}")]
    PackSegment(io::Error),
    #[error("failed to unpack segment data: {0}")]
    UnpackSegment(io::Error),
}

impl MemoryMappedSegmentStorageError {
    pub fn decode_metadata<E>(e: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::DecodeMetadata(anyhow::Error::new(e))
    }

    pub fn encode_metadata<E>(e: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::EncodeMetadata(anyhow::Error::new(e))
    }

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
            MemoryMappedSegmentStorageError::NoProjectPath => SegmentStorageError::NoProjectPath,
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
        File::create(project.join(PROJECT_MEMORY_MAPPING_DATA))
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
        let _ = fs::remove_file(project.join(PROJECT_MEMORY_MAPPING_META));

        Ok(Self {
            backing: Vec::new(),
            size,
            written: WrittenExtents::default(),
            project: project.to_owned(),
        })
    }

    pub fn open_existing(project_path: impl AsRef<Path>) -> Result<Self, SegmentStorageError> {
        let project = project_path.as_ref();
        let data_path = project.join(PROJECT_MEMORY_MAPPING_DATA);
        let meta_path = project.join(PROJECT_MEMORY_MAPPING_META);
        let file = match File::open(&data_path) {
            Ok(file) => file,
            Err(e) => {
                tracing::error!(
                    "memory-mapped storage data file at {} unavailable: {e}",
                    data_path.display()
                );
                return Err(MemoryMappedSegmentStorageError::no_project_data(project).into());
            }
        };

        let mut backing = Vec::new();
        let mut written = WrittenExtents::default();
        let size;
        if meta_path.exists() {
            let metadata_bytes =
                fs::read(&meta_path).map_err(MemoryMappedSegmentStorageError::UnpackSegment)?;
            let metadata =
                rkyv::access::<ArchivedPackMetadata, rkyv::rancor::Error>(&metadata_bytes)
                    .map_err(MemoryMappedSegmentStorageError::decode_metadata)?;
            size = metadata.logical_size.to_native();
            if !metadata.extents.is_empty() {
                let packed = unsafe { Mmap::map(&file) }
                    .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
                let mut source = 0usize;
                let mut first = 0;
                while first < metadata.extents.len() {
                    let base = metadata.extents[first].offset.to_native();
                    let mut end = base + metadata.extents[first].size.to_native();
                    let mut last = first + 1;
                    while last < metadata.extents.len() {
                        let extent = &metadata.extents[last];
                        let offset = extent.offset.to_native();
                        if offset.saturating_sub(end) > MAX_BACKING_GAP {
                            break;
                        }
                        end = offset + extent.size.to_native();
                        last += 1;
                    }
                    let mut segment = MappedBacking::new(project, base, end - base)?;
                    for extent in &metadata.extents[first..last] {
                        let offset = extent.offset.to_native();
                        let length = usize::try_from(extent.size.to_native())
                            .map_err(|_| SegmentStorageError::InvalidSize)?;
                        let target = usize::try_from(offset - base)
                            .map_err(|_| SegmentStorageError::InvalidSize)?;
                        segment.mapping[target..target + length]
                            .copy_from_slice(&packed[source..source + length]);
                        source += length;
                        written.insert(offset..offset + length as u64);
                    }
                    backing.push(segment);
                    first = last;
                }
            }
        } else {
            size = file
                .metadata()
                .map_err(MemoryMappedSegmentStorageError::UnpackSegment)?
                .len();
            if size != 0 {
                let flat = unsafe { Mmap::map(&file) }
                    .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
                let mut segment = MappedBacking::new(project, 0, size)?;
                segment.mapping.copy_from_slice(&flat);
                backing.push(segment);
                written.insert(0..size);
            }
        }

        Ok(Self {
            backing,
            size,
            written,
            project: project.to_owned(),
        })
    }

    fn pack(&mut self) -> Result<(), SegmentStorageError> {
        let mut data_file = File::create(self.project.join(PROJECT_MEMORY_MAPPING_DATA))
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
        let mut extents = Vec::new();
        for range in self.written.iter() {
            extents.push(PackExtent::new(range.start, range.end - range.start));
            let first = self
                .backing
                .partition_point(|backing| backing.end <= range.start);
            for backing in &self.backing[first..] {
                if backing.base >= range.end {
                    break;
                }
                let start = (range.start.max(backing.base) - backing.base) as usize;
                let end = (range.end.min(backing.end) - backing.base) as usize;
                data_file
                    .write_all(&backing.mapping[start..end])
                    .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
            }
        }
        data_file
            .sync_all()
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;

        let metadata = PackMetadata::new(self.size, extents);
        let meta_file = File::create(self.project.join(PROJECT_MEMORY_MAPPING_META))
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
        let writer = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(
            &metadata,
            rkyv::ser::writer::IoWriter::new(meta_file),
        )
        .map_err(MemoryMappedSegmentStorageError::encode_metadata)?;
        writer
            .into_inner()
            .sync_all()
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
        Ok(())
    }

    #[inline(never)]
    fn read_bytes_from_backing(
        &self,
        offset: u64,
        bytes: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        let available = self.size.saturating_sub(offset);
        let read_size = bytes
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        if read_size == 0 {
            return if bytes.is_empty() {
                Ok(0)
            } else {
                Err(SegmentStorageError::InvalidAddress)
            };
        }
        let end = offset + read_size as u64;

        let mut cursor = offset;
        let first = self
            .backing
            .partition_point(|backing| backing.end <= offset);
        for backing in &self.backing[first..] {
            if backing.base >= end {
                break;
            }
            let from = offset.max(backing.base);
            let to = end.min(backing.end);
            bytes[(cursor - offset) as usize..(from - offset) as usize].fill(0);
            bytes[(from - offset) as usize..(to - offset) as usize].copy_from_slice(
                &backing.mapping[(from - backing.base) as usize..(to - backing.base) as usize],
            );
            cursor = to;
        }
        bytes[(cursor - offset) as usize..read_size].fill(0);
        Ok(read_size)
    }
}

impl<const PERSISTENCE: StoragePersistence> Drop for MemoryMappedSegmentStorage<PERSISTENCE> {
    fn drop(&mut self) {
        if PERSISTENCE == storage::PERSISTENT {
            if let Err(e) = self.pack() {
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
        id: SegmentStorageProviderId,
        range: RangeInclusive<Address>,
        attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        let project_root = attributes
            .get_attr::<PathBuf>(ATTRIBUTE_PROJECT_PATH)
            .ok_or(MemoryMappedSegmentStorageError::NoProjectPath)?;
        let project = id.path_in(&project_root);

        let data_path = project.join(PROJECT_MEMORY_MAPPING_DATA);

        let size = range
            .size()
            .filter(|&size| size > 0)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;

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
        if let [backing] = self.backing.as_slice()
            && let Some(start) = offset.checked_sub(backing.base)
            && let Ok(start) = usize::try_from(start)
            && let Some(source) = backing.mapping.get(start..)
            && let Some(source) = source.get(..bytes.len())
        {
            bytes.copy_from_slice(source);
            return Ok(bytes.len());
        }

        cold_path();
        self.read_bytes_from_backing(offset, bytes)
    }

    fn write_bytes(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, SegmentStorageError> {
        let available = self.size.saturating_sub(offset);
        let write_size = bytes
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        if write_size == 0 {
            return if bytes.is_empty() {
                Ok(0)
            } else {
                Err(SegmentStorageError::InvalidAddress)
            };
        }
        let end = offset + write_size as u64;
        let mut cursor = offset;
        while cursor < end {
            let next = self
                .backing
                .partition_point(|backing| backing.base <= cursor);
            let limit = self
                .backing
                .get(next)
                .map_or(self.size, |backing| backing.base);
            let to = end.min(limit);
            let index = if next > 0
                && cursor.saturating_sub(self.backing[next - 1].end) <= MAX_BACKING_GAP
            {
                next - 1
            } else {
                let backing = MappedBacking::new(&self.project, cursor, to - cursor)?;
                self.backing.insert(next, backing);
                next
            };
            let backing = &mut self.backing[index];
            let required = to - backing.base;
            let capacity = backing.mapping.len() as u64;
            if required > capacity {
                let capacity = required
                    .max(capacity.saturating_add(capacity.min(MAX_BACKING_GAP)))
                    .min(limit - backing.base);
                backing.resize(capacity)?;
            }
            let start = (cursor - backing.base) as usize;
            let length = (to - cursor) as usize;
            backing.mapping[start..start + length]
                .copy_from_slice(&bytes[(cursor - offset) as usize..(to - offset) as usize]);
            backing.end = backing.end.max(to);
            self.written.insert(cursor..to);
            cursor = to;
        }
        Ok(write_size)
    }

    fn view_bytes(&self, offset: u64, n: usize) -> Result<SegmentView<'_>, SegmentStorageError> {
        if offset >= self.size {
            return Err(SegmentStorageError::InvalidAddress);
        }
        let end = offset
            .checked_add(n as u64)
            .filter(|&end| end <= self.size)
            .ok_or(SegmentStorageError::InvalidSize)?;
        let mut view = SegmentView::new(n as u64);
        for run in self.written.runs_in(offset..end) {
            let first = if self.backing.len() == 1 {
                0
            } else {
                self.backing
                    .partition_point(|backing| backing.end <= run.start)
            };
            for backing in &self.backing[first..] {
                if backing.base >= run.end {
                    break;
                }
                let from = run.start.max(backing.base);
                let to = run.end.min(backing.end);
                view.push(
                    from - offset,
                    &backing.mapping[(from - backing.base) as usize..(to - backing.base) as usize],
                );
            }
        }
        Ok(view)
    }

    fn view_bytes_from(&self, offset: u64) -> Result<SegmentView<'_>, SegmentStorageError> {
        if offset >= self.size {
            return Err(SegmentStorageError::InvalidAddress);
        }
        let mut view = SegmentView::default();
        if let Some(run) = self.written.run_at(offset) {
            view.set_size(run.end - offset);
            let first = if self.backing.len() == 1 {
                0
            } else {
                self.backing
                    .partition_point(|backing| backing.end <= offset)
            };
            for backing in &self.backing[first..] {
                if backing.base >= run.end {
                    break;
                }
                let from = offset.max(backing.base);
                let to = run.end.min(backing.end);
                view.push(
                    from - offset,
                    &backing.mapping[(from - backing.base) as usize..(to - backing.base) as usize],
                );
            }
        }
        Ok(view)
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn resize(&mut self, new_size: u64) -> Result<(), SegmentStorageError> {
        if new_size < self.size {
            let retained = self
                .backing
                .partition_point(|backing| backing.base < new_size);
            if let Some(backing) = self.backing[..retained].last_mut()
                && backing.mapping.len() as u64 > new_size - backing.base
            {
                backing.resize(new_size - backing.base)?;
                backing.end = backing.end.min(new_size);
            }
            self.backing.truncate(retained);
            let mut written = WrittenExtents::default();
            for run in self.written.runs_in(0..new_size) {
                written.insert(run);
            }
            self.written = written;
        }
        self.size = new_size;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SegmentStorageError> {
        for backing in &self.backing {
            backing
                .mapping
                .flush()
                .map_err(MemoryMappedSegmentStorageError::FlushMapping)?;
        }
        Ok(())
    }
}
