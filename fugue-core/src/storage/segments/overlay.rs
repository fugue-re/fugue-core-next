use std::collections::BTreeMap;
use std::ops::Bound;

use smallvec::SmallVec;

use crate::ir::RawAddress;

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

    pub fn size(&self) -> usize {
        self.data.len()
    }
}

#[derive(Debug, Clone, Default)]
pub struct OverlayTree {
    chunks: BTreeMap<RawAddress, OverlayChunk>,
}

impl OverlayTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn iter(&self) -> impl Iterator<Item = (RawAddress, &OverlayChunk)> {
        self.chunks.iter().map(|(&key, value)| (key, value))
    }

    pub fn write(&mut self, addr: impl Into<RawAddress>, data: impl Into<Vec<u8>>) {
        let data = data.into();
        if data.is_empty() {
            return;
        }

        let addr = addr.into();
        let start = match self.chunks.range_mut(..=addr).next_back() {
            Some((&start, chunk)) if start + chunk.size() >= addr => {
                let offset = usize::from(addr - start);
                let overlap = (chunk.size() - offset).min(data.len());
                chunk.data[offset..offset + overlap].copy_from_slice(&data[..overlap]);
                chunk.data.extend_from_slice(&data[overlap..]);
                start
            }
            _ => {
                self.chunks.insert(addr, OverlayChunk::new(data));
                addr
            }
        };

        let mut end = start + self.chunks[&start].size();
        while let Some((&next, _)) = self
            .chunks
            .range((Bound::Excluded(start), Bound::Unbounded))
            .next()
            .filter(|&(&next, _)| next <= end)
        {
            let next_chunk = self
                .chunks
                .remove(&next)
                .expect("following overlay chunk exists");
            if let Some(tail) = next_chunk.data.get(usize::from(end - next)..) {
                let chunk = self
                    .chunks
                    .get_mut(&start)
                    .expect("current overlay chunk exists");
                chunk.data.extend_from_slice(tail);
                end = start + chunk.size();
            }
        }
    }

    pub fn clear_range(&mut self, addr: impl Into<RawAddress>, size: usize) {
        if size == 0 {
            return;
        }

        let addr = addr.into();
        let end = addr + size;
        let first = self
            .chunks
            .range(..=addr)
            .next_back()
            .map_or(addr, |(&start, _)| start);
        let overlapping = self
            .chunks
            .range(first..)
            .take_while(|&(&start, _)| start < end)
            .filter_map(|(&start, chunk)| (start + chunk.size() > addr).then_some(start))
            .collect::<SmallVec<[_; 4]>>();

        for start in overlapping {
            let mut chunk = self
                .chunks
                .remove(&start)
                .expect("overlapping overlay chunk exists");

            if start + chunk.size() > end {
                let right = chunk.data.split_off(usize::from(end - start));
                self.chunks.insert(end, OverlayChunk::new(right));
            }
            if start < addr {
                chunk.data.truncate(usize::from(addr - start));
                self.chunks.insert(start, chunk);
            }
        }
    }

    pub fn read(&self, addr: impl Into<RawAddress>, buffer: &mut [u8]) -> usize {
        if buffer.is_empty() {
            return 0;
        }

        let addr = addr.into();
        let read_end = RawAddress::from(addr.offset().saturating_add(buffer.len() as u64));
        let mut bytes_applied = 0;

        let first = self
            .chunks
            .range(..=addr)
            .next_back()
            .map_or(addr, |(&start, _)| start);

        for (&chunk_start, chunk) in self.chunks.range(first..read_end) {
            let chunk_end = chunk_start + chunk.size();

            if chunk_end <= addr {
                continue;
            }

            let overlap_start = addr.max(chunk_start);
            let overlap_end = read_end.min(chunk_end);

            let buffer_start = usize::from(overlap_start - addr);
            let buffer_end = usize::from(overlap_end - addr);
            let chunk_offset = usize::from(overlap_start - chunk_start);
            let chunk_size = usize::from(overlap_end - overlap_start);

            buffer[buffer_start..buffer_end]
                .copy_from_slice(&chunk.data[chunk_offset..chunk_offset + chunk_size]);
            bytes_applied += chunk_size;
        }

        bytes_applied
    }

    pub fn chunk_covering(
        &self,
        addr: impl Into<RawAddress>,
    ) -> Option<(RawAddress, &OverlayChunk)> {
        let addr = addr.into();
        self.chunks
            .range(..=addr)
            .next_back()
            .and_then(|(&start, chunk)| {
                (addr.checked_offset_from(start)? < chunk.size() as u64).then_some((start, chunk))
            })
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
    fn test_sequential_writes_coalesce() {
        let mut tree = OverlayTree::new();
        tree.write(0x100u64, vec![1u8, 2, 3, 4]);
        tree.write(0x104u64, vec![5u8, 6, 7, 8]);
        tree.write(0x108u64, vec![9u8, 10]);

        assert_eq!(tree.iter().count(), 1, "adjacent chunks coalesce");
        let (start, chunk) = tree.chunk_covering(0x100u64).unwrap();
        assert_eq!(start, RawAddress::from(0x100u64));
        assert_eq!(chunk.data(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }
}
