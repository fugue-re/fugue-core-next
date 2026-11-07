use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::ops::{Range, RangeInclusive};
use std::path::{Path, PathBuf};

use fugue_core_derive::SegmentStorageProvider;
use memmap2::MmapMut;
use smallvec::SmallVec;

use crate::ir::{Address, AddressRangeExt};
use crate::storage::segments::SegmentStorageError;
use crate::storage::segments::provider::memmap::{
    MemoryMappedSegmentStorageError, PROJECT_MEMORY_MAPPING_DATA, PROJECT_MEMORY_MAPPING_META,
};
use crate::storage::segments::provider::{
    SegmentStorageProvider, SegmentStorageProviderFromSegmentRange,
    SegmentStorageProviderFromStorage, SegmentStorageProviderId, SegmentView,
};
use crate::storage::{self, PERSISTENT, StoragePersistence, TRANSIENT};
use crate::types::AttributeMap;
use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PackExtent {
    offset: u64,
    size: u64,
    file_offset: u64,
}

impl PackExtent {
    fn new(offset: u64, size: u64, file_offset: u64) -> Self {
        Self {
            offset,
            size,
            file_offset,
        }
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PackMetadata {
    logical_size: u64,
    file_end: u64,
    extents: Vec<PackExtent>,
}

impl PackMetadata {
    fn new(logical_size: u64, file_end: u64, extents: Vec<PackExtent>) -> Self {
        Self {
            logical_size,
            file_end,
            extents,
        }
    }

    fn persist(&self, project: &Path) -> Result<(), SegmentStorageError> {
        let meta_file = File::create(project.join(PROJECT_MEMORY_MAPPING_META))
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
        let writer = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(
            self,
            rkyv::ser::writer::IoWriter::new(meta_file),
        )
        .map_err(MemoryMappedSegmentStorageError::encode_metadata)?;
        writer
            .into_inner()
            .sync_all()
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct MappedExtent {
    size: u64,
    file_offset: u64,
}

impl MappedExtent {
    fn new(size: u64, file_offset: u64) -> Self {
        Self { size, file_offset }
    }

    fn file_range(&self, start: u64, from: u64, to: u64) -> Range<usize> {
        let first = self.file_offset + (from - start);
        let last = first + (to - from);
        usize::try_from(first).expect("mapped extents lie within the mapping")
            ..usize::try_from(last).expect("mapped extents lie within the mapping")
    }
}

struct ExtentPlacement {
    source: u64,
    target: u64,
    size: u64,
}

impl ExtentPlacement {
    fn new(source: u64, target: u64, size: u64) -> Self {
        Self {
            source,
            target,
            size,
        }
    }

    fn relocate(&self, backing: &mut [u8], base: u64) {
        let source = usize::try_from(self.source).expect("packed extents lie within the mapping");
        let target =
            usize::try_from(base + self.target).expect("packed extents lie within the mapping");
        let size = usize::try_from(self.size).expect("packed extents lie within the mapping");
        if source != target {
            backing.copy_within(source..source + size, target);
        }
    }
}

#[derive(SegmentStorageProvider)]
#[provider(
    concrete = PackedMemoryMappedSegmentStorage<{ PERSISTENT }>,
    tag = "packed-memory-mapped-persistent",
)]
#[provider(
    concrete = PackedMemoryMappedSegmentStorage<{ TRANSIENT }>,
    tag = "packed-memory-mapped-transient",
    persistent = false,
)]
pub struct PackedMemoryMappedSegmentStorage<const PERSISTENCE: StoragePersistence> {
    backing: MmapMut,
    extents: BTreeMap<u64, MappedExtent>,
    file: File,
    file_end: u64,
    last_extent: Option<u64>,
    project: PathBuf,
    size: u64,
}

impl<const PERSISTENCE: StoragePersistence> PackedMemoryMappedSegmentStorage<PERSISTENCE> {
    pub fn with_size(
        project_path: impl AsRef<Path>,
        size: u64,
    ) -> Result<Self, SegmentStorageError> {
        let project = project_path.as_ref();

        fs::create_dir_all(project).map_err(MemoryMappedSegmentStorageError::CreateProject)?;

        let data_path = project.join(PROJECT_MEMORY_MAPPING_DATA);

        tracing::trace!(
            "creating memory-mapped storage at {} spanning {size} bytes",
            data_path.display(),
        );

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&data_path)
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;

        let _ = fs::remove_file(project.join(PROJECT_MEMORY_MAPPING_META));

        let backing = unsafe { MmapMut::map_mut(&file) }
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;

        Ok(Self {
            backing,
            extents: BTreeMap::new(),
            file,
            file_end: 0,
            last_extent: None,
            project: project.to_owned(),
            size,
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
                    "memory-mapped storage data file at {} unavailable: {e}",
                    data_path.display()
                );
                return Err(MemoryMappedSegmentStorageError::no_project_data(project).into());
            }
        };

        if !meta_path.exists() {
            tracing::error!(
                "memory-mapped storage metadata at {} unavailable",
                meta_path.display()
            );
            return Err(MemoryMappedSegmentStorageError::no_project_data(project).into());
        }

        tracing::trace!("opening packed segment data at {}", data_path.display());

        let metadata_bytes =
            fs::read(&meta_path).map_err(MemoryMappedSegmentStorageError::UnpackSegment)?;
        let metadata = rkyv::access::<ArchivedPackMetadata, rkyv::rancor::Error>(&metadata_bytes)
            .map_err(MemoryMappedSegmentStorageError::decode_metadata)?;

        let mut extents = BTreeMap::new();
        let file_end = metadata.file_end.to_native();
        for extent in metadata.extents.iter() {
            extents.insert(
                extent.offset.to_native(),
                MappedExtent::new(extent.size.to_native(), extent.file_offset.to_native()),
            );
        }

        let backing = unsafe { MmapMut::map_mut(&file) }
            .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
        let last_extent = extents
            .iter()
            .find(|(_, extent)| extent.file_offset + extent.size == file_end)
            .map(|(start, _)| *start);

        Ok(Self {
            backing,
            extents,
            file,
            file_end,
            last_extent,
            project: project.to_owned(),
            size: metadata.logical_size.to_native(),
        })
    }

    fn pack_in_place(&mut self) -> Result<(), SegmentStorageError> {
        let mut placements = Vec::with_capacity(self.extents.len());
        let mut extents = Vec::<PackExtent>::new();
        let mut compacted = 0u64;
        let mut in_place = true;
        let mut source_end = 0u64;

        for (&start, extent) in &self.extents {
            in_place &= extent.file_offset >= compacted && extent.file_offset >= source_end;
            source_end = extent.file_offset + extent.size;
            placements.push(ExtentPlacement::new(
                extent.file_offset,
                compacted,
                extent.size,
            ));
            match extents.last_mut() {
                Some(previous) if previous.offset + previous.size == start => {
                    previous.size += extent.size;
                }
                _ => extents.push(PackExtent::new(start, extent.size, compacted)),
            }
            compacted += extent.size;
        }

        if in_place {
            for placement in &placements {
                placement.relocate(&mut self.backing, 0);
            }
        } else {
            let scratch = self.file_end;
            let required = scratch + compacted;
            let capacity = self.backing.len() as u64;
            if required > capacity {
                self.file
                    .set_len(required.max(capacity.saturating_mul(2)))
                    .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
                self.backing = unsafe { MmapMut::map_mut(&self.file) }
                    .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
            }
            for placement in &placements {
                placement.relocate(&mut self.backing, scratch);
            }
            ExtentPlacement::new(scratch, 0, compacted).relocate(&mut self.backing, 0);
        }

        if !self.backing.is_empty() {
            self.backing
                .flush()
                .map_err(MemoryMappedSegmentStorageError::FlushMapping)?;
        }
        self.file
            .set_len(compacted)
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;
        self.file
            .sync_all()
            .map_err(MemoryMappedSegmentStorageError::PackSegment)?;

        PackMetadata::new(self.size, compacted, extents).persist(&self.project)
    }
}

impl<const PERSISTENCE: StoragePersistence> Drop for PackedMemoryMappedSegmentStorage<PERSISTENCE> {
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

impl SegmentStorageProviderFromStorage for PackedMemoryMappedSegmentStorage<{ PERSISTENT }> {
    fn from_storage(
        path: impl AsRef<Path>,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        Self::open_existing(path)
    }
}

impl<const PERSISTENCE: StoragePersistence> SegmentStorageProviderFromSegmentRange
    for PackedMemoryMappedSegmentStorage<PERSISTENCE>
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
    for PackedMemoryMappedSegmentStorage<PERSISTENCE>
{
    fn read_bytes(&self, offset: u64, bytes: &mut [u8]) -> Result<usize, SegmentStorageError> {
        let available = self.size.saturating_sub(offset);
        let read_size = bytes
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));

        if read_size == 0 && !bytes.is_empty() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let buffer = &mut bytes[..read_size];
        let mut cursor = offset;

        let end = offset + read_size as u64;
        let index = |position: u64| {
            usize::try_from(position - offset).expect("the position lies within the read")
        };
        for (&start, extent) in self
            .extents
            .range(..offset)
            .next_back()
            .filter(|(start, extent)| **start + extent.size > offset)
            .into_iter()
            .chain(self.extents.range(offset..end))
        {
            let from = start.max(offset);
            let to = (start + extent.size).min(end);
            buffer[index(cursor)..index(from)].fill(0);
            buffer[index(from)..index(to)]
                .copy_from_slice(&self.backing[extent.file_range(start, from, to)]);
            cursor = to;
        }

        buffer[index(cursor)..].fill(0);
        Ok(read_size)
    }

    fn write_bytes(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, SegmentStorageError> {
        let available = self.size.saturating_sub(offset);
        let write_size = bytes
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));

        if write_size == 0 && !bytes.is_empty() {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let end = offset + write_size as u64;
        let index = |position: u64| {
            usize::try_from(position - offset).expect("the position lies within the write")
        };

        let mut holes = SmallVec::<[Range<u64>; 2]>::new();
        let mut cursor = offset;
        for (&start, extent) in self
            .extents
            .range(..offset)
            .next_back()
            .filter(|(start, extent)| **start + extent.size > offset)
            .into_iter()
            .chain(self.extents.range(offset..end))
        {
            if start > cursor {
                holes.push(cursor..start);
            }
            let from = start.max(offset);
            let to = (start + extent.size).min(end);
            self.backing[extent.file_range(start, from, to)]
                .copy_from_slice(&bytes[index(from)..index(to)]);
            cursor = to;
        }
        if cursor < end {
            holes.push(cursor..end);
        }

        for hole in holes {
            let bytes = &bytes[index(hole.start)..index(hole.end)];
            let size = bytes.len() as u64;
            let (key, extent) = match self.last_extent.and_then(|last| {
                let extent = self.extents[&last];
                (last + extent.size == hole.start).then_some((last, extent))
            }) {
                Some((last, extent)) => (
                    last,
                    MappedExtent::new(extent.size + size, extent.file_offset),
                ),
                None => (hole.start, MappedExtent::new(size, self.file_end)),
            };

            let required = self.file_end + size;
            let capacity = self.backing.len() as u64;
            if required > capacity {
                self.file
                    .set_len(required.max(capacity.saturating_mul(2)))
                    .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
                self.backing = unsafe { MmapMut::map_mut(&self.file) }
                    .map_err(MemoryMappedSegmentStorageError::CreateMapping)?;
            }
            let first =
                usize::try_from(self.file_end).expect("the file end lies within the mapping");
            self.backing[first..first + bytes.len()].copy_from_slice(bytes);

            self.file_end += size;
            self.extents.insert(key, extent);
            self.last_extent = Some(key);
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
        for (&start, extent) in self
            .extents
            .range(..offset)
            .next_back()
            .filter(|(start, extent)| **start + extent.size > offset)
            .into_iter()
            .chain(self.extents.range(offset..end))
        {
            let from = start.max(offset);
            let to = (start + extent.size).min(end);
            view.push(
                from - offset,
                &self.backing[extent.file_range(start, from, to)],
            );
        }

        Ok(view)
    }

    fn view_bytes_from(&self, offset: u64) -> Result<SegmentView<'_>, SegmentStorageError> {
        if offset >= self.size {
            return Err(SegmentStorageError::InvalidAddress);
        }

        let mut view = SegmentView::default();
        if let Some((&start, extent)) = self
            .extents
            .range(..=offset)
            .next_back()
            .filter(|(start, extent)| **start + extent.size > offset)
        {
            let to = start + extent.size;
            view.push(0, &self.backing[extent.file_range(start, offset, to)]);
            view.set_size(to - offset);
        }

        Ok(view)
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn resize(&mut self, new_size: u64) -> Result<(), SegmentStorageError> {
        if new_size < self.size {
            self.extents.split_off(&new_size);
            if let Some((&start, extent)) = self.extents.range_mut(..new_size).next_back()
                && start + extent.size > new_size
            {
                extent.size = new_size - start;
            }
            if self.last_extent.is_some_and(|last| {
                self.extents
                    .get(&last)
                    .is_none_or(|extent| extent.file_offset + extent.size != self.file_end)
            }) {
                self.last_extent = None;
            }
        }

        self.size = new_size;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SegmentStorageError> {
        if !self.backing.is_empty() {
            self.backing
                .flush()
                .map_err(MemoryMappedSegmentStorageError::FlushMapping)?;
        }
        if PERSISTENCE == storage::PERSISTENT {
            self.file
                .sync_all()
                .map_err(MemoryMappedSegmentStorageError::FlushMapping)?;
            let extents = self
                .extents
                .iter()
                .map(|(&offset, extent)| PackExtent::new(offset, extent.size, extent.file_offset))
                .collect();
            PackMetadata::new(self.size, self.file_end, extents).persist(&self.project)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sparse_view_queries_written_extents() -> Result<(), SegmentStorageError> {
        let dir = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let mut store = PackedMemoryMappedSegmentStorage::<{ TRANSIENT }>::with_size(&dir, 0x40)?;
        store.write_bytes(0x10, b"ab")?;
        store.write_bytes(0x12, b"cd")?;
        store.write_bytes(0x20, b"wxyz")?;

        let view = store.view_bytes(0x11, 0x12)?;
        assert_eq!(view.size(), 0x12);
        assert_eq!(view.chunks().len(), 2);
        assert_eq!(view.chunks()[0].offset(), 0);
        assert_eq!(view.chunks()[0].bytes(), b"bcd");
        assert_eq!(view.chunks()[1].offset(), 0x0f);
        assert_eq!(view.chunks()[1].bytes(), b"wxy");

        let run = store.view_bytes_from(0x11)?;
        assert_eq!(run.as_contiguous(), Some(&b"bcd"[..]));

        let gap = store.view_bytes_from(0x18)?;
        assert!(gap.is_empty());
        assert!(gap.chunks().is_empty());
        Ok(())
    }

    #[test]
    fn test_pack_roundtrip_sparse() -> Result<(), SegmentStorageError> {
        let dir = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let logical = 0x10_0000u64;

        {
            let mut store =
                PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, logical)?;
            store.write_bytes(0x10, b"hello")?;
            store.write_bytes(0x8_0000, b"world")?;
        }

        let data_path = dir.path().join(PROJECT_MEMORY_MAPPING_DATA);
        let packed_len = fs::metadata(&data_path).unwrap().len();
        assert!(
            packed_len < 0x1000,
            "packed file must be proportional to written bytes, not logical size (got {packed_len})"
        );

        let store = PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
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
        Ok(())
    }

    #[test]
    fn test_pack_post_load_write() -> Result<(), SegmentStorageError> {
        let dir = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let logical = 0x10_0000u64;

        {
            let mut store =
                PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, logical)?;
            store.write_bytes(0x10, b"hello")?;
        }
        {
            let mut store =
                PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
            store.write_bytes(0x200, b"patch")?;
        }

        let store = PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
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
        Ok(())
    }

    #[test]
    fn test_pack_fully_initialised() -> Result<(), SegmentStorageError> {
        let dir = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let payload = (0..0x20u8).collect::<Vec<_>>();

        {
            let mut store =
                PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, 0x20)?;
            store.write_bytes(0, &payload)?;
        }

        let store = PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
        assert_eq!(store.size(), 0x20);
        let mut buf = [0u8; 0x20];
        store.read_bytes(0, &mut buf)?;
        assert_eq!(&buf[..], &payload[..]);

        drop(store);
        Ok(())
    }

    #[test]
    fn test_pack_empty() -> Result<(), SegmentStorageError> {
        let dir = tempfile::tempdir().map_err(SegmentStorageError::backing)?;

        {
            PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, 0x1000)?;
        }

        let store = PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
        assert_eq!(store.size(), 0x1000);
        let mut buf = [0xffu8; 32];
        store.read_bytes(0x400, &mut buf)?;
        assert!(buf.iter().all(|byte| *byte == 0));

        drop(store);
        Ok(())
    }

    #[test]
    fn test_segment_ranges_use_distinct_provider_storage() -> Result<(), SegmentStorageError> {
        let dir = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let mut attributes = AttributeMap::new();
        attributes.set_attr(ATTRIBUTE_PROJECT_PATH, dir.path().to_path_buf());

        {
            let mut first = PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::from_segment_range(
                SegmentStorageProviderId::new(0),
                Address::from(0u64)..=Address::from(31u64),
                &mut attributes,
            )?;
            let mut second =
                PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::from_segment_range(
                    SegmentStorageProviderId::new(1),
                    Address::from(0u64)..=Address::from(63u64),
                    &mut attributes,
                )?;
            first.write_bytes(0, b"first")?;
            second.write_bytes(0, b"second")?;
        }

        let first = PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(
            SegmentStorageProviderId::new(0).path_in(dir.path()),
        )?;
        let second = PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(
            SegmentStorageProviderId::new(1).path_in(dir.path()),
        )?;
        let mut first_bytes = [0u8; 5];
        let mut second_bytes = [0u8; 6];
        first.read_bytes(0, &mut first_bytes)?;
        second.read_bytes(0, &mut second_bytes)?;

        assert_eq!(&first_bytes, b"first");
        assert_eq!(&second_bytes, b"second");
        assert_eq!(first.size(), 32);
        assert_eq!(second.size(), 64);

        drop(first);
        drop(second);
        Ok(())
    }

    #[test]
    fn test_distant_extents() -> Result<(), SegmentStorageError> {
        let dir = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let high = 1u64 << 47;

        {
            let mut store =
                PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, high + 0x1000)?;
            store.write_bytes(0x10, b"low")?;
            store.write_bytes(high, b"high")?;

            let view = store.view_bytes_from(high)?;
            assert_eq!(view.as_contiguous(), Some(&b"high"[..]));
        }

        let data_path = dir.path().join(PROJECT_MEMORY_MAPPING_DATA);
        let packed_len = fs::metadata(&data_path).unwrap().len();
        assert_eq!(packed_len, 7);

        let store = PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
        assert_eq!(store.size(), high + 0x1000);
        let mut low = [0u8; 3];
        store.read_bytes(0x10, &mut low)?;
        assert_eq!(&low, b"low");
        let mut far = [0u8; 4];
        store.read_bytes(high, &mut far)?;
        assert_eq!(&far, b"high");

        drop(store);
        Ok(())
    }

    #[test]
    fn test_bridging_write() -> Result<(), SegmentStorageError> {
        let dir = tempfile::tempdir().map_err(SegmentStorageError::backing)?;

        {
            let mut store =
                PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::with_size(&dir, 0x200)?;
            store.write_bytes(0x100, b"aaaa")?;
            store.write_bytes(0x108, b"bbbb")?;
            store.write_bytes(0x102, b"XXXXXXXX")?;
        }

        let store = PackedMemoryMappedSegmentStorage::<{ PERSISTENT }>::open_existing(&dir)?;
        let view = store.view_bytes_from(0x100)?;
        assert_eq!(view.as_contiguous(), Some(&b"aaXXXXXXXXbb"[..]));

        Ok(())
    }

    #[test]
    fn resize_grows_and_cuts() -> Result<(), SegmentStorageError> {
        let dir = tempfile::tempdir().map_err(SegmentStorageError::backing)?;
        let mut store = PackedMemoryMappedSegmentStorage::<{ TRANSIENT }>::with_size(&dir, 0x10)?;
        store.write_bytes(0x8, b"abcdefgh")?;

        store.resize(0x100)?;
        store.write_bytes(0x80, b"grown")?;
        let mut grown = [0u8; 5];
        store.read_bytes(0x80, &mut grown)?;
        assert_eq!(&grown, b"grown");

        store.resize(0xc)?;
        assert!(store.read_bytes(0x80, &mut grown).is_err());
        let view = store.view_bytes_from(0x8)?;
        assert_eq!(view.as_contiguous(), Some(&b"abcd"[..]));

        Ok(())
    }
}
