use smallvec::SmallVec;

use crate::ir::{Address, AddressRange, AddressRangeSet, Symbol};
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[repr(transparent)]
pub struct Revision(u64);

impl Revision {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0
    }

    pub const fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionChangeKind {
    Body,
    Frame,
    Name,
    Properties,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ChangeKinds: u16 {
        const BYTES_WRITTEN           = 0x0001;
        const FUNCTION_ADDED          = 0x0002;
        const FUNCTION_CHANGED        = 0x0004;
        const FUNCTION_REMOVED        = 0x0008;
        const RESTORED                = 0x0010;
        const SEGMENT_MAPPED          = 0x0020;
        const SEGMENT_MAPPING_CHANGED = 0x0040;
        const SEGMENT_MAPPING_CREATED = 0x0080;
        const SEGMENT_UNMAPPED        = 0x0100;
        const SPACE_CREATED           = 0x0200;
        const SYMBOL_ADDED            = 0x0400;
        const SYMBOL_REMOVED          = 0x0800;

        const FUNCTIONS = Self::FUNCTION_ADDED.bits()
            | Self::FUNCTION_CHANGED.bits()
            | Self::FUNCTION_REMOVED.bits();
        const SYMBOLS = Self::SYMBOL_ADDED.bits() | Self::SYMBOL_REMOVED.bits();
        const SEGMENTS = Self::SEGMENT_MAPPED.bits()
            | Self::SEGMENT_UNMAPPED.bits()
            | Self::SEGMENT_MAPPING_CREATED.bits()
            | Self::SEGMENT_MAPPING_CHANGED.bits();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeRecord {
    BytesWritten {
        range: AddressRange,
    },
    FunctionAdded {
        entry: Address,
        coverage: AddressRangeSet,
    },
    FunctionChanged {
        entry: Address,
        kind: FunctionChangeKind,
        coverage: AddressRangeSet,
    },
    FunctionRemoved {
        entry: Address,
        coverage: AddressRangeSet,
    },
    Restored {
        to: Revision,
    },
    SegmentMapped {
        mapping: SegmentMappingId,
        range: AddressRange,
    },
    SegmentMappingChanged {
        mapping: SegmentMappingId,
    },
    SegmentMappingCreated {
        mapping: SegmentMappingId,
    },
    SegmentUnmapped {
        mapping: SegmentMappingId,
        range: AddressRange,
    },
    SpaceCreated {
        space: AddressSpaceId,
    },
    SymbolAdded {
        address: Address,
        symbol: Symbol,
    },
    SymbolRemoved {
        address: Address,
        symbol: Symbol,
    },
}

impl ChangeRecord {
    pub fn kind(&self) -> ChangeKinds {
        match self {
            Self::BytesWritten { .. } => ChangeKinds::BYTES_WRITTEN,
            Self::FunctionAdded { .. } => ChangeKinds::FUNCTION_ADDED,
            Self::FunctionChanged { .. } => ChangeKinds::FUNCTION_CHANGED,
            Self::FunctionRemoved { .. } => ChangeKinds::FUNCTION_REMOVED,
            Self::Restored { .. } => ChangeKinds::RESTORED,
            Self::SegmentMapped { .. } => ChangeKinds::SEGMENT_MAPPED,
            Self::SegmentMappingChanged { .. } => ChangeKinds::SEGMENT_MAPPING_CHANGED,
            Self::SegmentMappingCreated { .. } => ChangeKinds::SEGMENT_MAPPING_CREATED,
            Self::SegmentUnmapped { .. } => ChangeKinds::SEGMENT_UNMAPPED,
            Self::SpaceCreated { .. } => ChangeKinds::SPACE_CREATED,
            Self::SymbolAdded { .. } => ChangeKinds::SYMBOL_ADDED,
            Self::SymbolRemoved { .. } => ChangeKinds::SYMBOL_REMOVED,
        }
    }

    pub fn ranges(&self) -> SmallVec<[AddressRange; 4]> {
        match self {
            Self::BytesWritten { range }
            | Self::SegmentMapped { range, .. }
            | Self::SegmentUnmapped { range, .. } => [*range].into_iter().collect(),
            Self::FunctionAdded { coverage, .. }
            | Self::FunctionChanged { coverage, .. }
            | Self::FunctionRemoved { coverage, .. } => coverage.ranges().collect(),
            Self::SymbolAdded { address, .. } | Self::SymbolRemoved { address, .. } => {
                [AddressRange::point(*address)].into_iter().collect()
            }
            Self::Restored { .. }
            | Self::SegmentMappingChanged { .. }
            | Self::SegmentMappingCreated { .. }
            | Self::SpaceCreated { .. } => SmallVec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSet {
    revision: Revision,
    records: Vec<ChangeRecord>,
    kinds: ChangeKinds,
}

impl ChangeSet {
    pub fn new(revision: Revision) -> Self {
        Self {
            revision,
            records: Vec::new(),
            kinds: ChangeKinds::empty(),
        }
    }

    pub fn with_records(revision: Revision, records: impl Into<Vec<ChangeRecord>>) -> Self {
        let records = records.into();
        let kinds = records
            .iter()
            .fold(ChangeKinds::empty(), |kinds, record| kinds | record.kind());
        Self {
            revision,
            records,
            kinds,
        }
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn records(&self) -> &[ChangeRecord] {
        &self.records
    }

    pub fn kinds(&self) -> ChangeKinds {
        self.kinds
    }

    pub fn contains(&self, kinds: ChangeKinds) -> bool {
        self.kinds.intersects(kinds)
    }

    pub fn records_matching(&self, kinds: ChangeKinds) -> impl Iterator<Item = &ChangeRecord> + '_ {
        let selected = self.contains(kinds);
        self.records
            .iter()
            .filter(move |record| selected && kinds.intersects(record.kind()))
    }

    pub fn into_records(self) -> Vec<ChangeRecord> {
        self.records
    }

    pub fn push(&mut self, record: ChangeRecord) {
        self.kinds |= record.kind();
        self.records.push(record);
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn scoped_to(&self, filter: &ChangeFilter) -> Option<ChangeSet> {
        if !self.contains(filter.kinds) {
            return None;
        }

        let scoped = self
            .records
            .iter()
            .filter(|record| filter.matches(record))
            .cloned()
            .collect::<Vec<_>>();

        if scoped.is_empty() {
            None
        } else {
            Some(Self::with_records(self.revision, scoped))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeFilter {
    kinds: ChangeKinds,
    region: Option<AddressRangeSet>,
}

impl Default for ChangeFilter {
    fn default() -> Self {
        Self {
            kinds: ChangeKinds::all(),
            region: None,
        }
    }
}

impl ChangeFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_kinds(mut self, kinds: ChangeKinds) -> Self {
        self.kinds = kinds;
        self
    }

    pub fn with_region(mut self, region: AddressRangeSet) -> Self {
        self.region = Some(region);
        self
    }

    pub fn kinds(&self) -> ChangeKinds {
        self.kinds
    }

    pub fn region(&self) -> Option<&AddressRangeSet> {
        self.region.as_ref()
    }

    pub fn matches(&self, record: &ChangeRecord) -> bool {
        if !self.kinds.intersects(record.kind()) {
            return false;
        }

        let Some(region) = self.region.as_ref() else {
            return true;
        };

        let ranges = record.ranges();
        ranges.is_empty() || ranges.iter().any(|range| region.intersects_range(range))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::{Address, RawAddress};
    use crate::storage::segments::space::AddressSpaceId;

    fn function_record(entry: u64) -> ChangeRecord {
        let entry = Address::from(entry);
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(entry));
        ChangeRecord::FunctionAdded { entry, coverage }
    }

    fn bytes_record(start: u64, end: u64) -> ChangeRecord {
        ChangeRecord::BytesWritten {
            range: AddressRange::new(
                AddressSpaceId::from(0u8),
                RawAddress::from(start),
                RawAddress::from(end),
            ),
        }
    }

    #[test]
    fn test_change_kinds_composites_equal_union() {
        assert_eq!(
            ChangeKinds::FUNCTIONS,
            ChangeKinds::FUNCTION_ADDED
                | ChangeKinds::FUNCTION_CHANGED
                | ChangeKinds::FUNCTION_REMOVED
        );
        assert_eq!(
            ChangeKinds::SYMBOLS,
            ChangeKinds::SYMBOL_ADDED | ChangeKinds::SYMBOL_REMOVED
        );
    }

    #[test]
    fn test_change_set_kinds_and_contains_agree_with_records() {
        let changes = ChangeSet::with_records(
            Revision::new(1),
            [function_record(0x1000), bytes_record(0x2000, 0x2fff)],
        );

        let expected = changes
            .records()
            .iter()
            .fold(ChangeKinds::empty(), |kinds, record| kinds | record.kind());
        assert_eq!(changes.kinds(), expected);

        assert!(changes.contains(ChangeKinds::FUNCTIONS));
        assert!(changes.contains(ChangeKinds::BYTES_WRITTEN));
        assert!(!changes.contains(ChangeKinds::SYMBOLS));
    }

    #[test]
    fn test_change_set_records_matching_equals_manual_scan() {
        let changes = ChangeSet::with_records(
            Revision::new(1),
            [
                function_record(0x1000),
                bytes_record(0x2000, 0x2fff),
                function_record(0x3000),
            ],
        );

        let matched = changes
            .records_matching(ChangeKinds::FUNCTIONS)
            .collect::<Vec<_>>();
        let manual = changes
            .records()
            .iter()
            .filter(|record| ChangeKinds::FUNCTIONS.intersects(record.kind()))
            .collect::<Vec<_>>();

        assert_eq!(matched, manual);
        assert_eq!(matched.len(), 2);
        assert!(
            changes
                .records_matching(ChangeKinds::SYMBOLS)
                .next()
                .is_none()
        );
    }

    #[test]
    fn test_record_ranges_report_locality() {
        assert_eq!(
            bytes_record(0x2000, 0x2fff).ranges().as_slice(),
            &[AddressRange::new(
                AddressSpaceId::from(0u8),
                RawAddress::from(0x2000u64),
                RawAddress::from(0x2fffu64)
            )]
        );
        assert_eq!(
            function_record(0x1000).ranges().as_slice(),
            &[AddressRange::point(Address::from(0x1000u64))]
        );
        assert!(
            ChangeRecord::Restored {
                to: Revision::new(1)
            }
            .ranges()
            .is_empty()
        );
    }
}
