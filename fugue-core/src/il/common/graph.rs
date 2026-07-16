use crate::il::common::{IlBlockId, IlIndexRange};

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
    pub struct IlBlockProperties: u16 {
        const ENTRY = 0x0001;
        const EXIT  = 0x0002;
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ArchivedIlBlockProperties(u16);

unsafe impl rkyv::Portable for ArchivedIlBlockProperties {}
unsafe impl rkyv::traits::NoUndef for ArchivedIlBlockProperties {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C>
    for ArchivedIlBlockProperties
where
    u16: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { u16::check_bytes(value.cast(), context) }
    }
}

impl rkyv::Archive for IlBlockProperties {
    type Archived = ArchivedIlBlockProperties;
    type Resolver = ();

    fn resolve(&self, _resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        out.write(ArchivedIlBlockProperties(self.bits()));
    }
}

impl<S: rkyv::rancor::Fallible + ?Sized> rkyv::Serialize<S> for IlBlockProperties {
    fn serialize(&self, _serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized> rkyv::Deserialize<IlBlockProperties, D>
    for ArchivedIlBlockProperties
{
    fn deserialize(&self, _deserializer: &mut D) -> Result<IlBlockProperties, D::Error> {
        Ok(IlBlockProperties::from_bits_retain(self.0))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct IlBlock {
    operations: IlIndexRange,
    successors: IlIndexRange,
    properties: IlBlockProperties,
}

impl IlBlock {
    pub(crate) const fn new(
        operations: IlIndexRange,
        successors: IlIndexRange,
        properties: IlBlockProperties,
    ) -> Self {
        Self {
            operations,
            successors,
            properties,
        }
    }

    pub const fn operations(&self) -> IlIndexRange {
        self.operations
    }

    pub const fn successors(&self) -> IlIndexRange {
        self.successors
    }

    pub const fn properties(&self) -> IlBlockProperties {
        self.properties
    }

    pub const fn is_entry(&self) -> bool {
        self.properties.contains(IlBlockProperties::ENTRY)
    }

    pub const fn is_exit(&self) -> bool {
        self.properties.contains(IlBlockProperties::EXIT)
    }
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct IlGraph {
    blocks: Vec<IlBlock>,
    successors: Vec<IlBlockId>,
}

impl IlGraph {
    pub(crate) fn new(blocks: Vec<IlBlock>, successors: Vec<IlBlockId>) -> Self {
        for block in &blocks {
            debug_assert!(
                block.successors().end() <= successors.len(),
                "block successor range is within the successor pool"
            );
        }

        for successor in &successors {
            debug_assert!(
                successor.index() < blocks.len(),
                "successor id is within the block count"
            );
        }

        Self { blocks, successors }
    }

    pub fn blocks(&self) -> &[IlBlock] {
        &self.blocks
    }

    pub fn successors(&self) -> &[IlBlockId] {
        &self.successors
    }

    pub fn entry_block(&self) -> Option<IlBlockId> {
        if self.blocks.is_empty() {
            return None;
        }

        let index = self.blocks.iter().position(IlBlock::is_entry).unwrap_or(0);

        Some(IlBlockId::try_from_index(index).expect("block count fits the block id space"))
    }

    pub fn predecessors(&self) -> IlBlockPredecessors {
        IlBlockPredecessors::build(&self.blocks, &self.successors)
    }

    pub fn shrink_to_fit(&mut self) {
        self.blocks.shrink_to_fit();
        self.successors.shrink_to_fit();
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IlBlockPredecessors {
    offsets: Vec<u32>,
    predecessors: Vec<IlBlockId>,
}

impl IlBlockPredecessors {
    pub(crate) fn build(blocks: &[IlBlock], successors: &[IlBlockId]) -> Self {
        let mut offsets = vec![0u32; blocks.len() + 1];

        for block in blocks {
            for successor in block.successors().slice(successors) {
                offsets[successor.index() + 1] += 1;
            }
        }

        for index in 1..offsets.len() {
            offsets[index] += offsets[index - 1];
        }

        let mut cursor = offsets.clone();
        let fill = IlBlockId::try_from_index(0).expect("block id zero is representable");
        let mut predecessors = vec![fill; *offsets.last().unwrap_or(&0) as usize];

        for (block_index, block) in blocks.iter().enumerate() {
            let block_id = IlBlockId::try_from_index(block_index)
                .expect("block count fits the block id space");

            for successor in block.successors().slice(successors) {
                let cursor_index = successor.index();
                let index = cursor[cursor_index] as usize;

                predecessors[index] = block_id;
                cursor[cursor_index] += 1;
            }
        }

        Self {
            offsets,
            predecessors,
        }
    }

    pub fn predecessors(&self, block: IlBlockId) -> &[IlBlockId] {
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

    pub fn values(&self) -> &[IlBlockId] {
        &self.predecessors
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn block_stays_compact() {
        assert!(size_of::<IlBlock>() <= 32);
    }

    #[test]
    fn empty_graph_has_no_entry_block() {
        assert_eq!(IlGraph::default().entry_block(), None);
    }

    #[test]
    fn entry_block_prefers_flagged_block() {
        let graph = IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::ENTRY,
                ),
            ],
            Vec::new(),
        );

        assert_eq!(graph.entry_block(), IlBlockId::try_from_index(1).ok());
    }

    #[test]
    fn predecessor_index_builds_from_successor_ranges() {
        let block0 = IlBlockId::try_from_index(0).unwrap();
        let block1 = IlBlockId::try_from_index(1).unwrap();
        let block2 = IlBlockId::try_from_index(2).unwrap();
        let blocks = vec![
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(0, 2).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::new(2, 3).unwrap(),
                IlBlockProperties::empty(),
            ),
            IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::empty(),
            ),
        ];
        let successors = vec![block1, block2, block2];
        let index = IlBlockPredecessors::build(&blocks, &successors);

        assert_eq!(index.predecessors(block0), &[]);
        assert_eq!(index.predecessors(block1), &[block0]);
        assert_eq!(index.predecessors(block2), &[block0, block1]);
    }
}
