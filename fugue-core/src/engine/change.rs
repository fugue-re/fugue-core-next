use crate::ir::{Address, AddressCoverage, RawAddress, Symbol};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum FunctionChangeKind {
    Body,
    Frame,
    Name,
    Properties,
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum ChangeRecord {
    BytesWritten {
        space: AddressSpaceId,
        range: (RawAddress, RawAddress),
    },
    FunctionAdded {
        entry: Address,
        coverage: AddressCoverage,
    },
    FunctionChanged {
        entry: Address,
        kind: FunctionChangeKind,
        coverage: AddressCoverage,
    },
    FunctionRemoved {
        entry: Address,
        coverage: AddressCoverage,
    },
    Restored {
        to: Revision,
    },
    SegmentMapped {
        mapping: SegmentMappingId,
        space: AddressSpaceId,
        range: (RawAddress, RawAddress),
    },
    SegmentMappingChanged {
        mapping: SegmentMappingId,
    },
    SegmentMappingCreated {
        mapping: SegmentMappingId,
    },
    SegmentUnmapped {
        mapping: SegmentMappingId,
        space: AddressSpaceId,
        range: (RawAddress, RawAddress),
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

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ChangeSet {
    revision: Revision,
    records: Vec<ChangeRecord>,
}

impl ChangeSet {
    pub fn new(revision: Revision) -> Self {
        Self {
            revision,
            records: Vec::new(),
        }
    }

    pub fn with_records(revision: Revision, records: impl Into<Vec<ChangeRecord>>) -> Self {
        Self {
            revision,
            records: records.into(),
        }
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn records(&self) -> &[ChangeRecord] {
        &self.records
    }

    pub fn into_records(self) -> Vec<ChangeRecord> {
        self.records
    }

    pub fn push(&mut self, record: ChangeRecord) {
        self.records.push(record);
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
}
