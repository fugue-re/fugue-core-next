use std::borrow::Cow;

use fallible_iterator::FallibleIterator;

use crate::ir::Address;
use crate::loader::{Loadable, LoadableSegment};
use crate::types::AttributeMap;

use super::{SegmentStorageError, SegmentStorageProvider, SegmentStorageProviderFromLoadable};

pub struct InMemorySegmentStorage {
    segments: Vec<LoadableSegment<'static>>,
}

impl InMemorySegmentStorage {
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
    ) -> Option<impl Iterator<Item = &LoadableSegment<'static>>> {
        let last_addr = addr + size;

        if last_addr < addr {
            return None;
        }

        let first = self.position(addr)?;

        // This allows us to have partial reads, e.g., when we'd read past the end of the last
        // segment.
        let last = self
            .position(last_addr)
            .unwrap_or_else(|| self.segments.len() - 1);

        let view = &self.segments[first..last + 1];

        for i in 0..view.len() - 1usize {
            if view[i].next_address() != view[i + 1].address() {
                // limit the view to this segment to allow partial reads
                return Some(view[..=i].iter());
            }
        }

        Some(view.iter())
    }

    fn overlapping_mut<'a>(
        &'a mut self,
        addr: Address,
        size: usize,
    ) -> Option<impl Iterator<Item = &'a mut LoadableSegment<'static>> + 'a> {
        let last_addr = addr + size;

        if last_addr < addr {
            return None;
        }

        let first = self.position(addr)?;
        let last = self
            .position(last_addr)
            .unwrap_or_else(|| self.segments.len() - 1);

        let view = &mut self.segments[first..last + 1];

        for i in 0..view.len() - 1usize {
            if view[i].next_address() != view[i + 1].address() {
                return Some(view[..=i].iter_mut());
            }
        }

        Some(view.iter_mut())
    }
}

impl SegmentStorageProviderFromLoadable for InMemorySegmentStorage {
    fn from_loadable(
        loader: &impl Loadable,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, SegmentStorageError> {
        let mut segments = Vec::new();
        let mut siter = loader.segments();

        while let Some(segm) = siter.next()? {
            tracing::trace!(
                "loading segment {} ({}-{}) into in-memory storage",
                segm.name(),
                segm.address(),
                segm.next_address()
            );
            segments.push(segm.into_owned());
        }

        segments.sort_by(|a, b| a.address().cmp(&b.address()));

        Ok(Self { segments })
    }
}

impl SegmentStorageProvider for InMemorySegmentStorage {
    fn read_bytes(&self, addr: Address, bytes: &mut [u8]) -> Result<usize, SegmentStorageError> {
        let mut size = bytes.len();
        let mut offset = 0;

        let addr = addr.into();

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

            let read_offset = usize::from(read_addr - segm_addr);
            let read_size = size.min(usize::from(segm_last_addr - read_addr) + 1);

            let segm_bytes = segm
                .view_bytes_at(read_offset, read_size)
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

        if bytes.is_empty() {
            return Ok(offset);
        }

        let segms = self
            .overlapping_mut(addr, size)
            .ok_or(SegmentStorageError::InvalidAddress)?;

        for segm in segms {
            let write_addr = addr + offset;

            let segm_addr = segm.address();
            let segm_last_addr = segm.last_address();

            let write_offset = usize::from(write_addr - segm_addr);
            let write_size = size.min(usize::from(segm_last_addr - write_addr) + 1);

            let segm_bytes = segm
                .view_bytes_at_mut(write_offset, write_size)
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

    fn contains_segment(&self, at: Address) -> bool {
        self.position(at).is_some()
    }

    fn find_segment_containing(
        &self,
        addr: Address,
    ) -> Result<Cow<LoadableSegment<'_>>, SegmentStorageError> {
        self.position(addr)
            .map(|pos| Cow::Borrowed(&self.segments[pos]))
            .ok_or(SegmentStorageError::InvalidAddress)
    }
}
