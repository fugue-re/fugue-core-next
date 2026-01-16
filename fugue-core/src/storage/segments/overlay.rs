use std::collections::BTreeMap;
use std::ops::Bound;

use bytes::Bytes;
use smallvec::SmallVec;

use crate::ir::Address;

#[derive(Debug, Clone)]
pub struct OverlayChunk {
    data: Bytes,
}

impl OverlayChunk {
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct OverlayTree {
    chunks: BTreeMap<Address, OverlayChunk>,
}

impl OverlayTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    pub fn write(&mut self, addr: impl Into<Address>, data: impl Into<Bytes>) {
        let data = data.into();
        if data.is_empty() {
            return;
        }

        let addr = addr.into();
        let write_end = addr + data.len();

        let overlapping = self
            .chunks
            .range(..write_end)
            .filter_map(|(&start, chunk)| {
                let chunk_end = start + chunk.len();
                if chunk_end > addr && start < write_end {
                    Some(start)
                } else {
                    None
                }
            })
            .collect::<SmallVec<[_; 4]>>();

        for start in overlapping {
            let chunk = self.chunks.remove(&start).unwrap();
            let chunk_end = start + chunk.len();

            if start < addr {
                let left_len = usize::from(addr - start);
                let left_data = chunk.data.slice(..left_len);
                self.chunks.insert(start, OverlayChunk::new(left_data));
            }

            if chunk_end > write_end {
                let right_start = usize::from(write_end - start);
                let right_data = chunk.data.slice(right_start..);
                self.chunks.insert(write_end, OverlayChunk::new(right_data));
            }
        }

        self.chunks.insert(addr, OverlayChunk::new(data));
        self.merge_adjacent(addr);
    }

    fn merge_adjacent(&mut self, addr: Address) {
        let chunk = match self.chunks.get(&addr) {
            Some(c) => c,
            None => return,
        };
        let chunk_end = addr + chunk.len();

        if let Some((&next_start, _)) = self
            .chunks
            .range((Bound::Excluded(addr), Bound::Unbounded))
            .next()
        {
            if next_start == chunk_end {
                let next_chunk = self.chunks.remove(&next_start).unwrap();
                let current = self.chunks.get_mut(&addr).unwrap();
                let mut merged = Vec::with_capacity(current.data.len() + next_chunk.data.len());
                merged.extend_from_slice(&current.data);
                merged.extend_from_slice(&next_chunk.data);
                current.data = Bytes::from(merged);
            }
        }

        let prev_entry = self
            .chunks
            .range(..addr)
            .next_back()
            .and_then(|(&start, chunk)| {
                if start + chunk.len() == addr {
                    Some(start)
                } else {
                    None
                }
            });

        if let Some(prev_start) = prev_entry {
            let current = self.chunks.remove(&addr).unwrap();
            let prev = self.chunks.get_mut(&prev_start).unwrap();
            let mut merged = Vec::with_capacity(prev.data.len() + current.data.len());
            merged.extend_from_slice(&prev.data);
            merged.extend_from_slice(&current.data);
            prev.data = Bytes::from(merged);
        }
    }

    pub fn read(&self, addr: impl Into<Address>, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }

        let addr = addr.into();
        let read_end = addr + buf.len();
        let mut bytes_applied = 0;

        for (&chunk_start, chunk) in self.chunks.range(..read_end) {
            let chunk_end = chunk_start + chunk.len();

            if chunk_end <= addr {
                continue;
            }

            let overlap_start = addr.max(chunk_start);
            let overlap_end = read_end.min(chunk_end);

            let buf_start = usize::from(overlap_start - addr);
            let buf_end = usize::from(overlap_end - addr);
            let chunk_offset = usize::from(overlap_start - chunk_start);
            let chunk_len = usize::from(overlap_end - overlap_start);

            buf[buf_start..buf_end]
                .copy_from_slice(&chunk.data[chunk_offset..chunk_offset + chunk_len]);
            bytes_applied += chunk_len;
        }

        bytes_applied
    }

    pub fn clear(&mut self) {
        self.chunks.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = (Address, &OverlayChunk)> {
        self.chunks.iter().map(|(&k, v)| (k, v))
    }

    pub fn total_size(&self) -> usize {
        self.chunks.values().map(|c| c.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_read_basic() {
        let mut tree = OverlayTree::new();
        tree.write(0u64, &b"hello"[..]);

        let mut buf = [0u8; 5];
        let read = tree.read(0u64, &mut buf);
        assert_eq!(read, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_write_overlapping() {
        let mut tree = OverlayTree::new();
        tree.write(0u64, &b"hello world"[..]);
        tree.write(6u64, &b"rust!"[..]);

        let mut buf = [0u8; 11];
        tree.read(0u64, &mut buf);
        assert_eq!(&buf, b"hello rust!");
    }

    #[test]
    fn test_write_partial_overlap_left() {
        let mut tree = OverlayTree::new();
        tree.write(5u64, &b"world"[..]);
        tree.write(0u64, &b"hello "[..]);

        let mut buf = [0u8; 10];
        tree.read(0u64, &mut buf);
        assert_eq!(&buf, b"hello orld");
    }

    #[test]
    fn test_read_partial() {
        let mut tree = OverlayTree::new();
        tree.write(0u64, &b"hello world"[..]);

        let mut buf = [0u8; 5];
        let read = tree.read(6u64, &mut buf);
        assert_eq!(read, 5);
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn test_clear() {
        let mut tree = OverlayTree::new();
        tree.write(0u64, &b"hello"[..]);
        assert!(!tree.is_empty());
        tree.clear();
        assert!(tree.is_empty());
    }
}
