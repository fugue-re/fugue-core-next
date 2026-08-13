use std::cmp::Ordering;

use crate::il::common::verify::StructureError;
use crate::il::common::{IlError, IlIndexRange};
use crate::ir::Address;

/// Maps a *destination* range of IL nodes back to the *source* machine
/// instruction they derive from.
///
/// Provenance bottoms out at the root dialect: every IL node at every level
/// ultimately derives from an instruction's pcode operations, so
/// `first_pcode_index`/`pcode_count` identify that micro-op range and are
/// carried through ECode and SSA unchanged — only `destination` is remapped
/// between levels.
#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct IlSourceSpan {
    destination: IlIndexRange,
    address: Address,
    first_pcode_index: u32,
    pcode_count: u32,
}

impl IlSourceSpan {
    pub(crate) const fn new(
        destination: IlIndexRange,
        address: Address,
        first_pcode_index: u32,
        pcode_count: u32,
    ) -> Self {
        Self {
            destination,
            address,
            first_pcode_index,
            pcode_count,
        }
    }

    pub const fn destination(&self) -> IlIndexRange {
        self.destination
    }

    pub const fn address(&self) -> Address {
        self.address
    }

    pub const fn first_pcode_index(&self) -> u32 {
        self.first_pcode_index
    }

    pub const fn pcode_count(&self) -> u32 {
        self.pcode_count
    }

    pub fn contains_source(&self, address: Address, pcode_index: u32) -> bool {
        self.address == address
            && self.first_pcode_index <= pcode_index
            && pcode_index - self.first_pcode_index < self.pcode_count
    }

    pub const fn contains_destination(&self, node: usize) -> bool {
        self.destination.start() <= node && node < self.destination.end()
    }

    pub fn find(spans: &[Self], node: usize) -> Option<Self> {
        spans
            .binary_search_by(|span| {
                if span.contains_destination(node) {
                    Ordering::Equal
                } else if node < span.destination().start() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            })
            .ok()
            .map(|index| spans[index])
    }

    pub fn find_all(
        spans: &[Self],
        address: Address,
        pcode_index: u32,
    ) -> impl Iterator<Item = Self> + '_ {
        spans
            .iter()
            .copied()
            .filter(move |span| span.contains_source(address, pcode_index))
    }

    pub fn try_merge(&mut self, span: IlSourceSpan) -> Result<bool, IlError> {
        if self.address != span.address
            || self.destination.end() != span.destination.start()
            || self.first_pcode_index + self.pcode_count != span.first_pcode_index
        {
            return Ok(false);
        }

        self.destination = IlIndexRange::new(self.destination.start(), span.destination.end())?;
        self.pcode_count += span.pcode_count;

        Ok(true)
    }

    pub(crate) fn verify(spans: &[Self], node_count: usize) -> Result<(), StructureError> {
        let mut previous_end = 0usize;

        for span in spans {
            span.destination.verify_bounds(node_count)?;

            if span.destination.start() < previous_end {
                return Err(StructureError::OverlappingSourceSpan {
                    node: span.destination.start() as u32,
                });
            }

            previous_end = span.destination.end();
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct IlParentSpan {
    destination: IlIndexRange,
    source: IlIndexRange,
}

impl IlParentSpan {
    pub(crate) const fn new(destination: IlIndexRange, source: IlIndexRange) -> Self {
        Self {
            destination,
            source,
        }
    }

    pub const fn destination(&self) -> IlIndexRange {
        self.destination
    }

    pub const fn source(&self) -> IlIndexRange {
        self.source
    }

    pub const fn contains_destination(&self, node: usize) -> bool {
        self.destination.start() <= node && node < self.destination.end()
    }

    pub(crate) fn verify(spans: &[Self], node_count: usize) -> Result<(), StructureError> {
        let mut previous_end = 0usize;

        for span in spans {
            span.destination.verify_bounds(node_count)?;
            span.source.verify_bounds(usize::MAX)?;

            if span.destination.start() < previous_end {
                return Err(StructureError::OverlappingParentSpan {
                    node: span.destination.start() as u32,
                });
            }

            previous_end = span.destination.end();
        }

        Ok(())
    }

    pub const fn contains_source(&self, node: usize) -> bool {
        self.source.start() <= node && node < self.source.end()
    }

    pub fn find(spans: &[Self], node: usize) -> Option<Self> {
        spans
            .binary_search_by(|span| {
                if span.contains_destination(node) {
                    Ordering::Equal
                } else if node < span.destination().start() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            })
            .ok()
            .map(|index| spans[index])
    }

    pub fn find_all(spans: &[Self], node: usize) -> impl Iterator<Item = Self> + '_ {
        spans
            .iter()
            .copied()
            .filter(move |span| span.contains_source(node))
    }

    pub fn try_merge(&mut self, span: IlParentSpan) -> Result<bool, IlError> {
        if self.destination.end() != span.destination.start()
            || self.source.end() != span.source.start()
        {
            return Ok(false);
        }

        self.destination = IlIndexRange::new(self.destination.start(), span.destination.end())?;
        self.source = IlIndexRange::new(self.source.start(), span.source.end())?;

        Ok(true)
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn mapping_records_stay_compact() {
        assert!(size_of::<IlSourceSpan>() <= 40);
        assert_eq!(size_of::<IlParentSpan>(), 16);
    }

    #[test]
    fn source_span_merges_adjacent_identical_provenance() {
        let address = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut span = IlSourceSpan::new(IlIndexRange::new(0, 2).unwrap(), address, 0, 2);

        assert!(
            span.try_merge(IlSourceSpan::new(
                IlIndexRange::new(2, 4).unwrap(),
                address,
                2,
                3
            ))
            .unwrap()
        );
        assert_eq!(span.destination(), IlIndexRange::new(0, 4).unwrap());
        assert_eq!(span.pcode_count(), 5);
        assert!(span.contains_destination(3));
        assert!(span.contains_source(address, 4));
    }

    #[test]
    fn source_span_keeps_distinct_fugue_spaces_separate() {
        let base = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let overlay = Address::new(AddressSpaceId::new(2), 0x1000u64);
        let mut span = IlSourceSpan::new(IlIndexRange::new(0, 1).unwrap(), base, 0, 1);

        assert!(
            !span
                .try_merge(IlSourceSpan::new(
                    IlIndexRange::new(1, 2).unwrap(),
                    overlay,
                    0,
                    1
                ))
                .unwrap()
        );
        assert!(span.contains_source(base, 0));
        assert!(!span.contains_source(overlay, 0));
    }

    #[test]
    fn parent_span_merges_adjacent_spans() {
        let mut span = IlParentSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::new(4, 6).unwrap(),
        );

        assert!(
            span.try_merge(IlParentSpan::new(
                IlIndexRange::new(2, 4).unwrap(),
                IlIndexRange::new(6, 8).unwrap(),
            ))
            .unwrap()
        );
        assert_eq!(span.source(), IlIndexRange::new(4, 8).unwrap());
        assert!(span.contains_destination(3));
        assert!(span.contains_source(7));
    }
}
