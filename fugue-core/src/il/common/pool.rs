use digest::Digest as _;
use sha2::Sha256;

use crate::il::common::{BlockId, IlError};

#[derive(
    Debug,
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct PackedRange {
    start: u32,
    end: u32,
}

impl PackedRange {
    pub const EMPTY: Self = Self { start: 0, end: 0 };

    pub fn new(start: usize, end: usize) -> Result<Self, IlError> {
        if start > end {
            return Err(IlError::reversed_range(
                u32::try_from(start).unwrap_or(u32::MAX),
                u32::try_from(end).unwrap_or(u32::MAX),
            ));
        }

        let start = u32::try_from(start).map_err(|_| IlError::integer_overflow("range start"))?;
        let end = u32::try_from(end).map_err(|_| IlError::integer_overflow("range end"))?;

        Ok(Self { start, end })
    }

    pub const fn start(&self) -> usize {
        self.start as usize
    }

    pub const fn end(&self) -> usize {
        self.end as usize
    }

    pub const fn len(&self) -> usize {
        (self.end - self.start) as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub const fn contains_index(&self, index: usize) -> bool {
        self.start() <= index && index < self.end()
    }

    pub fn checked_slice<'a, T>(&self, values: &'a [T]) -> Result<&'a [T], IlError> {
        self.verify_bounds(values.len())?;

        Ok(&values[self.start()..self.end()])
    }

    pub fn verify_bounds(&self, len: usize) -> Result<(), IlError> {
        if self.start > self.end {
            return Err(IlError::reversed_range(self.start, self.end));
        }

        if self.end() > len {
            return Err(IlError::range_out_of_bounds(self.end, len));
        }

        Ok(())
    }

    pub(crate) fn update_digest(&self, digest: &mut Sha256) {
        digest.update(self.start.to_be_bytes());
        digest.update(self.end.to_be_bytes());
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pool<T> {
    values: Vec<T>,
}

impl<T> Pool<T> {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub fn append(&mut self, values: impl IntoIterator<Item = T>) -> Result<PackedRange, IlError> {
        let start = self.values.len();
        self.values.extend(values);
        let end = self.values.len();

        PackedRange::new(start, end)
    }

    pub fn values(&self) -> &[T] {
        &self.values
    }

    pub fn into_values(self) -> Vec<T> {
        self.values
    }

    pub fn clear(&mut self) {
        self.values.clear();
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct Block {
    operations: PackedRange,
    successors: PackedRange,
    flags: u16,
}

impl Block {
    pub const ENTRY: u16 = 0x0001;
    pub const EXIT: u16 = 0x0002;

    pub const fn new(operations: PackedRange, successors: PackedRange, flags: u16) -> Self {
        Self {
            operations,
            successors,
            flags,
        }
    }

    pub const fn operations(&self) -> PackedRange {
        self.operations
    }

    pub const fn successors(&self) -> PackedRange {
        self.successors
    }

    pub const fn flags(&self) -> u16 {
        self.flags
    }

    pub const fn is_entry(&self) -> bool {
        self.flags & Self::ENTRY != 0
    }

    pub const fn is_exit(&self) -> bool {
        self.flags & Self::EXIT != 0
    }

    pub fn verify_successors(&self, block: BlockId, successors: &[BlockId]) -> Result<(), IlError> {
        let successors = self.successors.checked_slice(successors)?;

        for (index, successor) in successors.iter().enumerate() {
            if successors[..index].contains(successor) {
                return Err(IlError::duplicate_successor(
                    block.index(),
                    successor.index(),
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PredecessorIndex {
    offsets: Vec<u32>,
    predecessors: Vec<BlockId>,
}

impl PredecessorIndex {
    pub fn new(offsets: Vec<u32>, predecessors: Vec<BlockId>) -> Self {
        Self {
            offsets,
            predecessors,
        }
    }

    pub fn build(blocks: &[Block], successors: &[BlockId]) -> Result<Self, IlError> {
        let mut offsets = vec![0u32; blocks.len() + 1];

        for block in blocks {
            for successor in block.successors().checked_slice(successors)? {
                if successor.index() >= blocks.len() {
                    return Err(IlError::range_out_of_bounds(
                        successor.value(),
                        blocks.len(),
                    ));
                }

                let index = successor.index() + 1;
                offsets[index] = offsets[index]
                    .checked_add(1)
                    .ok_or(IlError::integer_overflow("predecessor count"))?;
            }
        }

        for index in 1..offsets.len() {
            offsets[index] = offsets[index]
                .checked_add(offsets[index - 1])
                .ok_or(IlError::integer_overflow("predecessor offset"))?;
        }

        let mut cursor = offsets.clone();
        let mut predecessors =
            vec![BlockId::try_from_index(0)?; *offsets.last().unwrap_or(&0) as usize];

        for (block_index, block) in blocks.iter().enumerate() {
            let block_id = BlockId::try_from_index(block_index)?;

            for successor in block.successors().checked_slice(successors)? {
                let cursor_index = successor.index();
                let index = cursor[cursor_index] as usize;

                predecessors[index] = block_id;
                cursor[cursor_index] += 1;
            }
        }

        Ok(Self {
            offsets,
            predecessors,
        })
    }

    pub fn predecessors(&self, block: BlockId) -> &[BlockId] {
        let Some(start) = self.offsets.get(block.index()).copied() else {
            return &[];
        };
        let end = self
            .offsets
            .get(block.index() + 1)
            .copied()
            .unwrap_or(start);

        &self.predecessors[start as usize..end as usize]
    }

    pub fn offsets(&self) -> &[u32] {
        &self.offsets
    }

    pub fn values(&self) -> &[BlockId] {
        &self.predecessors
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn common_records_stay_compact() {
        assert_eq!(size_of::<PackedRange>(), 8);
        assert!(size_of::<Block>() <= 32);
        assert_eq!(size_of::<BlockId>(), 4);
        assert_eq!(size_of::<Option<BlockId>>(), 4);
    }

    #[test]
    fn range_rejects_reversed_bounds() {
        assert!(matches!(
            PackedRange::new(3, 2),
            Err(IlError::ReversedRange { .. })
        ));
    }

    #[test]
    fn range_checked_slice_rejects_out_of_bounds() {
        let range = PackedRange::new(0, 2).unwrap();

        assert!(matches!(
            range.checked_slice(&[1u8]),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn range_checked_slice_rejects_archived_reversed_bounds() {
        let range = PackedRange { start: 2, end: 1 };

        assert!(matches!(
            range.checked_slice(&[1u8, 2]),
            Err(IlError::ReversedRange { .. })
        ));
    }

    #[test]
    fn block_rejects_duplicate_successors() {
        let block = Block::new(PackedRange::EMPTY, PackedRange::new(0, 2).unwrap(), 0);
        let successor = BlockId::try_from_index(0).unwrap();

        assert!(matches!(
            block.verify_successors(successor, &[successor, successor]),
            Err(IlError::DuplicateSuccessor { .. })
        ));
    }

    #[test]
    fn predecessor_index_builds_from_successor_ranges() {
        let block0 = BlockId::try_from_index(0).unwrap();
        let block1 = BlockId::try_from_index(1).unwrap();
        let block2 = BlockId::try_from_index(2).unwrap();
        let blocks = vec![
            Block::new(PackedRange::EMPTY, PackedRange::new(0, 2).unwrap(), 0),
            Block::new(PackedRange::EMPTY, PackedRange::new(2, 3).unwrap(), 0),
            Block::new(PackedRange::EMPTY, PackedRange::EMPTY, 0),
        ];
        let successors = vec![block1, block2, block2];
        let index = PredecessorIndex::build(&blocks, &successors).unwrap();

        assert_eq!(index.predecessors(block0), &[]);
        assert_eq!(index.predecessors(block1), &[block0]);
        assert_eq!(index.predecessors(block2), &[block0, block1]);
    }

    #[test]
    fn predecessor_index_rejects_out_of_range_successor() {
        let blocks = vec![Block::new(
            PackedRange::EMPTY,
            PackedRange::new(0, 1).unwrap(),
            0,
        )];
        let successors = vec![BlockId::try_from_index(1).unwrap()];

        assert!(matches!(
            PredecessorIndex::build(&blocks, &successors),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }
}
