use std::ops::RangeInclusive;

use crate::ir::{Address, AddressRangeExt};
use crate::storage::segments::SegmentStorageError;
use crate::storage::segments::overlay::OverlayTree;
use crate::storage::segments::provider::{
    SegmentRangeOverlap, SegmentStorageProvider, SegmentStorageProviderFromSegmentRange,
    SegmentStorageProviderId, SegmentView,
};
use crate::types::AttributeMap;

#[derive(crate::SegmentStorageProvider)]
#[provider(tag = "in-memory", persistent = false)]
pub struct InMemorySegmentStorage {
    base: usize,
    chunk: Vec<u8>,
    overlay: OverlayTree,
    size: usize,
}

impl InMemorySegmentStorage {
    pub fn with_size(size: usize) -> Self {
        Self {
            base: 0,
            chunk: Vec::new(),
            overlay: OverlayTree::new(),
            size,
        }
    }

    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        let chunk = bytes.into();
        let size = chunk.len();
        Self {
            base: 0,
            chunk,
            overlay: OverlayTree::new(),
            size,
        }
    }

    fn clamped_len(&self, offset: usize, len: usize) -> Result<usize, SegmentStorageError> {
        let available = self.size.saturating_sub(offset);
        let clamped = len.min(available);
        if clamped == 0 && len != 0 {
            return Err(SegmentStorageError::InvalidAddress);
        }
        Ok(clamped)
    }

    fn chunk_end(&self) -> usize {
        self.base + self.chunk.len()
    }

    fn chunk_contains(&self, offset: usize, len: usize) -> bool {
        !self.chunk.is_empty() && offset >= self.base && offset + len <= self.chunk_end()
    }
}

impl SegmentStorageProviderFromSegmentRange for InMemorySegmentStorage {
    fn from_segment_range(
        _id: SegmentStorageProviderId,
        range: RangeInclusive<Address>,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        let size = range
            .size()
            .filter(|&size| size > 0)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;

        tracing::trace!("creating sparse in-memory storage spanning {size} bytes");

        Ok(Self::with_size(size as usize))
    }
}

impl SegmentStorageProvider for InMemorySegmentStorage {
    fn read_bytes(&self, offset: u64, bytes: &mut [u8]) -> Result<usize, SegmentStorageError> {
        let offset = usize::try_from(offset).map_err(|_| SegmentStorageError::InvalidAddress)?;
        let read = self.clamped_len(offset, bytes.len())?;
        let buf = &mut bytes[..read];

        if self.chunk_contains(offset, read) {
            let start = offset - self.base;
            buf.copy_from_slice(&self.chunk[start..start + read]);
            return Ok(read);
        }

        buf.fill(0);
        self.overlay.read(offset as u64, buf);

        if let Some(o) =
            SegmentRangeOverlap::new(self.base, self.chunk.len(), offset, offset + read)
        {
            buf[o.window()].copy_from_slice(&self.chunk[o.source()]);
        }

        Ok(read)
    }

    fn write_bytes(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, SegmentStorageError> {
        let offset = usize::try_from(offset).map_err(|_| SegmentStorageError::InvalidAddress)?;
        let write = self.clamped_len(offset, bytes.len())?;
        let data = &bytes[..write];

        if self.chunk.is_empty() {
            self.base = offset;
            self.chunk = data.to_vec();
            return Ok(write);
        }

        let chunk_end = self.chunk_end();
        let end = offset + write;
        if offset < self.base && end > self.base {
            let prefix = self.base - offset;
            self.overlay.write(offset as u64, data[..prefix].to_vec());

            let remaining = &data[prefix..];
            let in_place = self.chunk.len().min(remaining.len());
            self.chunk[..in_place].copy_from_slice(&remaining[..in_place]);
            if remaining.len() > self.chunk.len() {
                self.chunk.extend_from_slice(&remaining[in_place..]);
            }
            self.overlay.clear_range(self.base as u64, self.chunk.len());
            return Ok(write);
        }

        if offset >= self.base && offset <= chunk_end {
            let local = offset - self.base;
            let in_place = chunk_end.min(end) - offset;
            self.chunk[local..local + in_place].copy_from_slice(&data[..in_place]);
            if end > chunk_end {
                self.chunk.extend_from_slice(&data[in_place..]);
            }
            self.overlay.clear_range(offset as u64, write);
            return Ok(write);
        }

        self.overlay.write(offset as u64, data.to_vec());
        Ok(write)
    }

    fn view_bytes(&self, offset: u64, n: usize) -> Result<SegmentView<'_>, SegmentStorageError> {
        let offset = usize::try_from(offset).map_err(|_| SegmentStorageError::InvalidAddress)?;
        if offset >= self.size {
            return Err(SegmentStorageError::InvalidAddress);
        }
        if n > self.size - offset {
            return Err(SegmentStorageError::InvalidSize);
        }

        if self.chunk_contains(offset, n) {
            let start = offset - self.base;
            return Ok(SegmentView::contiguous(&self.chunk[start..start + n]));
        }

        let end = offset + n;
        let mut view = SegmentView::new(n as u64);

        if let Some(o) = SegmentRangeOverlap::new(self.base, self.chunk.len(), offset, end) {
            view.push(o.window_offset() as u64, &self.chunk[o.source()]);
        }

        for (run, chunk) in self.overlay.iter() {
            if let Some(o) =
                SegmentRangeOverlap::new(run.offset() as usize, chunk.len(), offset, end)
            {
                view.push(o.window_offset() as u64, &chunk.data()[o.source()]);
            }
        }

        Ok(view)
    }

    fn view_bytes_from(&self, offset: u64) -> Result<SegmentView<'_>, SegmentStorageError> {
        let offset = usize::try_from(offset).map_err(|_| SegmentStorageError::InvalidAddress)?;
        if offset >= self.size {
            return Err(SegmentStorageError::InvalidAddress);
        }

        if !self.chunk.is_empty() && offset >= self.base && offset < self.chunk_end() {
            let start = offset - self.base;
            return Ok(SegmentView::contiguous(&self.chunk[start..]));
        }

        if let Some((run, chunk)) = self.overlay.chunk_covering(offset as u64) {
            let start = offset - run.offset() as usize;
            return Ok(SegmentView::contiguous(&chunk.data()[start..]));
        }

        Ok(SegmentView::default())
    }

    fn size(&self) -> u64 {
        self.size as u64
    }

    fn resize(&mut self, new_size: u64) -> Result<(), SegmentStorageError> {
        self.size = new_size as usize;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chunk_fast_path() -> Result<(), SegmentStorageError> {
        let mut store = InMemorySegmentStorage::with_size(0x1000);
        store.write_bytes(0, b"AAAA")?;
        store.write_bytes(4, b"BBBB")?;
        store.write_bytes(8, b"CCCC")?;

        assert!(
            store.overlay.is_empty(),
            "contiguous writes stay in the chunk"
        );
        assert_eq!(store.chunk.len(), 12);

        let view = store.view_bytes_from(2)?;
        assert_eq!(view.as_contiguous(), Some(&b"AABBBBCCCC"[..]));

        let mut buf = [0u8; 4];
        store.read_bytes(4, &mut buf)?;
        assert_eq!(&buf, b"BBBB");
        Ok(())
    }

    #[test]
    fn test_overwrite_in_place() -> Result<(), SegmentStorageError> {
        let mut store = InMemorySegmentStorage::with_size(0x1000);
        store.write_bytes(0, b"AAAAAAAA")?;
        store.write_bytes(2, b"xx")?;

        assert!(store.overlay.is_empty());
        assert_eq!(store.chunk.len(), 8, "overwrite does not grow the chunk");

        let mut buf = [0u8; 8];
        store.read_bytes(0, &mut buf)?;
        assert_eq!(&buf, b"AAxxAAAA");
        Ok(())
    }

    #[test]
    fn test_chunk_anchors_at_first_write() -> Result<(), SegmentStorageError> {
        let mut store = InMemorySegmentStorage::with_size(0x1000);
        store.write_bytes(0x100, b"data")?;

        assert_eq!(store.base, 0x100);
        assert!(store.overlay.is_empty());
        assert_eq!(store.chunk.len(), 4);

        let mut buf = [0xffu8; 4];
        store.read_bytes(0x100, &mut buf)?;
        assert_eq!(&buf, b"data");

        let mut gap = [0xffu8; 4];
        store.read_bytes(0, &mut gap)?;
        assert!(gap.iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn test_write_from_below_updates_chunk_overlap() -> Result<(), SegmentStorageError> {
        let mut store = InMemorySegmentStorage::with_size(0x1000);
        store.write_bytes(0x100, b"AAAA")?;
        store.write_bytes(0x0fe, b"bbbb")?;

        let mut bytes = [0u8; 6];
        store.read_bytes(0x0fe, &mut bytes)?;

        assert_eq!(&bytes, b"bbbbAA");
        Ok(())
    }

    #[test]
    fn test_sparse_outlier_and_gaps() -> Result<(), SegmentStorageError> {
        let mut store = InMemorySegmentStorage::with_size(0x1_0000);
        store.write_bytes(0, b"hello")?;
        store.write_bytes(0x8000, b"world")?;

        assert!(
            !store.overlay.is_empty(),
            "disjoint write goes to the overlay"
        );

        let mut buf = [0xffu8; 16];
        store.read_bytes(0, &mut buf)?;
        assert_eq!(&buf[..5], b"hello");
        assert!(buf[5..].iter().all(|byte| *byte == 0));

        let mut sparse = [0u8; 5];
        store.read_bytes(0x8000, &mut sparse)?;
        assert_eq!(&sparse, b"world");

        let mut gap = [0xffu8; 8];
        store.read_bytes(0x1000, &mut gap)?;
        assert!(gap.iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn chunk_growth_replaces_covered_overlay_bytes() -> Result<(), SegmentStorageError> {
        let mut store = InMemorySegmentStorage::with_size(0x1000);
        store.write_bytes(0, b"AAAA")?;
        store.write_bytes(8, b"old!")?;
        store.write_bytes(4, b"BBBBCCCC")?;

        let mut direct = [0u8; 12];
        store.read_bytes(0, &mut direct)?;
        let mut viewed = [0u8; 12];
        store.view_bytes(0, 12)?.read_into(&mut viewed);
        assert_eq!(&direct, b"AAAABBBBCCCC");
        assert_eq!(viewed, direct);
        Ok(())
    }

    #[test]
    fn test_view_spans_gap() -> Result<(), SegmentStorageError> {
        let mut store = InMemorySegmentStorage::with_size(0x1000);
        store.write_bytes(0, b"AAAA")?;
        store.write_bytes(8, b"BBBB")?;

        let view = store.view_bytes(0, 12)?;
        assert_eq!(view.size(), 12);
        assert_eq!(
            view.as_contiguous(),
            Some(&b"AAAA"[..]),
            "as_contiguous yields the leading run up to the gap"
        );

        let mut buf = [0xffu8; 12];
        view.read_into(&mut buf);
        assert_eq!(&buf, b"AAAA\0\0\0\0BBBB");

        let run = store.view_bytes_from(0)?;
        assert_eq!(run.size(), 4, "view_bytes_from stops at the chunk's end");
        Ok(())
    }
}
