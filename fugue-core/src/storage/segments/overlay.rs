use std::collections::BTreeMap;
use std::ops::Bound;

use smallvec::SmallVec;

use crate::ir::Address;

#[derive(Debug, Clone)]
pub struct OverlayChunk {
    data: Vec<u8>,
}

impl OverlayChunk {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
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

    pub fn write(&mut self, addr: impl Into<Address>, data: impl Into<Vec<u8>>) {
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
                (chunk_end > addr && start < write_end).then_some(start)
            })
            .collect::<SmallVec<[_; 4]>>();

        for start in overlapping {
            let mut chunk = self.chunks.remove(&start).unwrap();
            let chunk_end = start + chunk.len();

            match (start < addr, chunk_end > write_end) {
                (true, true) => {
                    let left_len = usize::from(addr - start);
                    let right_start = usize::from(write_end - start);
                    let right = chunk.data.split_off(right_start);
                    chunk.data.truncate(left_len);
                    self.chunks.insert(start, chunk);
                    self.chunks.insert(write_end, OverlayChunk::new(right));
                }
                (true, false) => {
                    let left_len = usize::from(addr - start);
                    chunk.data.truncate(left_len);
                    self.chunks.insert(start, chunk);
                }
                (false, true) => {
                    let right_start = usize::from(write_end - start);
                    chunk.data.drain(..right_start);
                    self.chunks.insert(write_end, chunk);
                }
                (false, false) => {}
            }
        }

        self.chunks.insert(addr, OverlayChunk::new(data));
        self.merge_adjacent(addr);
    }

    fn merge_adjacent(&mut self, addr: Address) {
        let Some(chunk) = self.chunks.get(&addr) else {
            return;
        };
        let chunk_end = addr + chunk.len();

        if let Some((&next_start, _)) = self
            .chunks
            .range((Bound::Excluded(addr), Bound::Unbounded))
            .next()
            && next_start == chunk_end
        {
            let next = self.chunks.remove(&next_start).unwrap();
            let current = self.chunks.get_mut(&addr).unwrap();
            current.data.extend_from_slice(&next.data);
        }

        let prev_start = self
            .chunks
            .range(..addr)
            .next_back()
            .and_then(|(&start, chunk)| (start + chunk.len() == addr).then_some(start));

        if let Some(prev_start) = prev_start {
            let current = self.chunks.remove(&addr).unwrap();
            let prev = self.chunks.get_mut(&prev_start).unwrap();
            prev.data.extend_from_slice(&current.data);
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

    pub fn chunk_covering(&self, addr: impl Into<Address>) -> Option<(Address, &OverlayChunk)> {
        let addr = addr.into();
        self.chunks
            .range(..=addr)
            .next_back()
            .and_then(|(&start, chunk)| {
                (addr.checked_offset_from(start)? < chunk.len() as u64).then_some((start, chunk))
            })
    }

    pub fn total_size(&self) -> usize {
        self.chunks.values().map(|c| c.len()).sum()
    }
}

#[cfg(test)]
mod test {
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

    #[test]
    fn test_sequential_writes_coalesce() {
        let mut tree = OverlayTree::new();
        tree.write(0x100u64, vec![1u8, 2, 3, 4]);
        tree.write(0x104u64, vec![5u8, 6, 7, 8]);
        tree.write(0x108u64, vec![9u8, 10]);

        assert_eq!(tree.iter().count(), 1, "adjacent chunks coalesce");
        let (start, chunk) = tree.chunk_covering(0x100u64).unwrap();
        assert_eq!(start, Address::from(0x100u64));
        assert_eq!(chunk.data(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }
}
