use std::cmp::Ordering;

use digest::Digest as _;
use sha2::Sha256;

use crate::il::common::{DialectId, IlError, IrLevel, PackedRange};
use crate::ir::Address;

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
pub struct SourceRun {
    destination: PackedRange,
    machine_address: Address,
    first_pcode_index: u32,
    pcode_count: u32,
}

impl SourceRun {
    pub const fn new(
        destination: PackedRange,
        machine_address: Address,
        first_pcode_index: u32,
        pcode_count: u32,
    ) -> Self {
        Self {
            destination,
            machine_address,
            first_pcode_index,
            pcode_count,
        }
    }

    pub const fn destination(&self) -> PackedRange {
        self.destination
    }

    pub const fn machine_address(&self) -> Address {
        self.machine_address
    }

    pub const fn first_pcode_index(&self) -> u32 {
        self.first_pcode_index
    }

    pub const fn pcode_count(&self) -> u32 {
        self.pcode_count
    }

    pub fn contains_source(&self, machine_address: Address, pcode_index: u32) -> bool {
        self.machine_address == machine_address
            && self
                .first_pcode_index
                .checked_add(self.pcode_count)
                .is_some_and(|end| self.first_pcode_index <= pcode_index && pcode_index < end)
    }

    pub const fn contains_destination(&self, node: u32) -> bool {
        self.destination.start() <= node as usize && (node as usize) < self.destination.end()
    }

    pub fn try_merge(&mut self, run: SourceRun) -> Result<bool, IlError> {
        if self.machine_address != run.machine_address
            || self.destination.end() != run.destination.start()
            || self.first_pcode_index.checked_add(self.pcode_count) != Some(run.first_pcode_index)
        {
            return Ok(false);
        }

        self.destination = PackedRange::new(self.destination.start(), run.destination.end())?;
        self.pcode_count = self
            .pcode_count
            .checked_add(run.pcode_count)
            .ok_or(IlError::integer_overflow("source run pcode count"))?;

        Ok(true)
    }

    pub(crate) fn update_digest(&self, digest: &mut Sha256) {
        self.destination.update_digest(digest);
        digest.update((self.machine_address.space().index() as u64).to_be_bytes());
        digest.update(self.machine_address.offset().to_be_bytes());
        digest.update(self.first_pcode_index.to_be_bytes());
        digest.update(self.pcode_count.to_be_bytes());
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceMap {
    runs: Vec<SourceRun>,
}

impl SourceMap {
    pub fn new() -> Self {
        Self { runs: Vec::new() }
    }

    pub fn add_run(&mut self, run: SourceRun) -> Result<(), IlError> {
        if let Some(previous) = self.runs.last_mut() {
            if previous.destination().end() > run.destination().start() {
                return Err(IlError::overlapping_source_run(
                    run.destination().start() as u32
                ));
            }

            if previous.try_merge(run)? {
                return Ok(());
            }
        }

        self.runs.push(run);
        Ok(())
    }

    pub fn runs(&self) -> &[SourceRun] {
        &self.runs
    }

    pub fn source_for_destination(&self, node: u32) -> Option<SourceRun> {
        self.runs
            .binary_search_by(|run| {
                if run.contains_destination(node) {
                    Ordering::Equal
                } else if node < run.destination().start() as u32 {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            })
            .ok()
            .map(|index| self.runs[index])
    }

    pub fn destinations_for_source(
        &self,
        machine_address: Address,
        pcode_index: u32,
    ) -> impl Iterator<Item = SourceRun> + '_ {
        self.runs
            .iter()
            .copied()
            .filter(move |run| run.contains_source(machine_address, pcode_index))
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
pub struct MappingRun {
    destination: PackedRange,
    source: PackedRange,
}

impl MappingRun {
    pub const fn new(destination: PackedRange, source: PackedRange) -> Self {
        Self {
            destination,
            source,
        }
    }

    pub const fn destination(&self) -> PackedRange {
        self.destination
    }

    pub const fn source(&self) -> PackedRange {
        self.source
    }

    pub const fn contains_destination(&self, node: u32) -> bool {
        self.destination.start() <= node as usize && (node as usize) < self.destination.end()
    }

    pub const fn contains_source(&self, node: u32) -> bool {
        self.source.start() <= node as usize && (node as usize) < self.source.end()
    }

    pub fn try_merge(&mut self, run: MappingRun) -> Result<bool, IlError> {
        if self.destination.end() != run.destination.start()
            || self.source.end() != run.source.start()
        {
            return Ok(false);
        }

        self.destination = PackedRange::new(self.destination.start(), run.destination.end())?;
        self.source = PackedRange::new(self.source.start(), run.source.end())?;

        Ok(true)
    }

    pub(crate) fn update_digest(&self, digest: &mut Sha256) {
        self.destination.update_digest(digest);
        self.source.update_digest(digest);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossLevelMap {
    parent: IrLevel,
    parent_dialect: DialectId,
    runs: Vec<MappingRun>,
}

impl CrossLevelMap {
    pub fn new(parent: IrLevel, parent_dialect: DialectId) -> Self {
        Self {
            parent,
            parent_dialect,
            runs: Vec::new(),
        }
    }

    pub fn add_run(&mut self, run: MappingRun) -> Result<(), IlError> {
        if let Some(previous) = self.runs.last_mut() {
            if previous.destination().end() > run.destination().start() {
                return Err(IlError::overlapping_mapping_run(
                    run.destination().start() as u32
                ));
            }

            if previous.try_merge(run)? {
                return Ok(());
            }
        }

        self.runs.push(run);
        Ok(())
    }

    pub const fn parent(&self) -> IrLevel {
        self.parent
    }

    pub const fn parent_dialect(&self) -> DialectId {
        self.parent_dialect
    }

    pub fn runs(&self) -> &[MappingRun] {
        &self.runs
    }

    pub fn parent_for_destination(&self, node: u32) -> Option<MappingRun> {
        self.runs
            .binary_search_by(|run| {
                if run.contains_destination(node) {
                    Ordering::Equal
                } else if node < run.destination().start() as u32 {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            })
            .ok()
            .map(|index| self.runs[index])
    }

    pub fn destinations_for_source(&self, node: u32) -> impl Iterator<Item = MappingRun> + '_ {
        self.runs
            .iter()
            .copied()
            .filter(move |run| run.contains_source(node))
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn mapping_records_stay_compact() {
        assert!(size_of::<SourceRun>() <= 40);
        assert_eq!(size_of::<MappingRun>(), 16);
    }

    #[test]
    fn source_map_merges_adjacent_identical_provenance() {
        let address = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut map = SourceMap::new();

        map.add_run(SourceRun::new(
            PackedRange::new(0, 2).unwrap(),
            address,
            0,
            2,
        ))
        .unwrap();
        map.add_run(SourceRun::new(
            PackedRange::new(2, 4).unwrap(),
            address,
            2,
            3,
        ))
        .unwrap();

        assert_eq!(map.runs().len(), 1);
        assert_eq!(map.runs()[0].destination(), PackedRange::new(0, 4).unwrap());
        assert_eq!(map.runs()[0].pcode_count(), 5);
        assert_eq!(map.source_for_destination(3), Some(map.runs()[0]));
        assert_eq!(map.destinations_for_source(address, 4).count(), 1);
    }

    #[test]
    fn source_map_keeps_distinct_fugue_spaces_separate() {
        let base = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let overlay = Address::new(AddressSpaceId::new(2), 0x1000u64);
        let mut map = SourceMap::new();

        map.add_run(SourceRun::new(PackedRange::new(0, 1).unwrap(), base, 0, 1))
            .unwrap();
        map.add_run(SourceRun::new(
            PackedRange::new(1, 2).unwrap(),
            overlay,
            0,
            1,
        ))
        .unwrap();

        assert_eq!(map.runs().len(), 2);
        assert_eq!(map.destinations_for_source(base, 0).count(), 1);
        assert_eq!(map.destinations_for_source(overlay, 0).count(), 1);
    }

    #[test]
    fn cross_level_map_merges_adjacent_runs_and_queries_both_ways() {
        let mut map = CrossLevelMap::new(IrLevel::PCode, DialectId::PCODE);

        map.add_run(MappingRun::new(
            PackedRange::new(0, 2).unwrap(),
            PackedRange::new(4, 6).unwrap(),
        ))
        .unwrap();
        map.add_run(MappingRun::new(
            PackedRange::new(2, 4).unwrap(),
            PackedRange::new(6, 8).unwrap(),
        ))
        .unwrap();

        assert_eq!(map.runs().len(), 1);
        assert_eq!(
            map.parent_for_destination(3).unwrap().source(),
            PackedRange::new(4, 8).unwrap()
        );
        assert_eq!(map.destinations_for_source(7).count(), 1);
    }
}
