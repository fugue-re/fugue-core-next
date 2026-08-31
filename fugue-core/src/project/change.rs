use std::sync::Arc;

use smallvec::SmallVec;
use smol_str::SmolStr;

use crate::il::common::IlFormId;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, ProblemKind, ProblemScope, ReferenceKind,
    ReferenceTarget, Symbol,
};
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;
use crate::types::Revision;

pub(crate) const MAX_DETAILED_CHANGE_RECORDS: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeCategory {
    Agent,
    Analysis,
    Engine,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChangeSource {
    category: ChangeCategory,
    label: SmolStr,
}

impl ChangeSource {
    pub fn agent(label: impl Into<SmolStr>) -> Self {
        Self {
            category: ChangeCategory::Agent,
            label: label.into(),
        }
    }

    pub fn analysis(label: impl Into<SmolStr>) -> Self {
        Self {
            category: ChangeCategory::Analysis,
            label: label.into(),
        }
    }

    pub fn engine(label: impl Into<SmolStr>) -> Self {
        Self {
            category: ChangeCategory::Engine,
            label: label.into(),
        }
    }

    pub fn other(label: impl Into<SmolStr>) -> Self {
        Self {
            category: ChangeCategory::Other,
            label: label.into(),
        }
    }

    pub fn category(&self) -> ChangeCategory {
        self.category
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

impl From<&str> for ChangeSource {
    fn from(label: &str) -> Self {
        Self::other(label)
    }
}

impl From<String> for ChangeSource {
    fn from(label: String) -> Self {
        Self::other(label)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeProvenance {
    sources: SmallVec<[ChangeSource; 2]>,
}

impl ChangeProvenance {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn of(source: impl Into<ChangeSource>) -> Self {
        Self {
            sources: [source.into()].into_iter().collect(),
        }
    }

    pub fn sources(&self) -> impl Iterator<Item = &ChangeSource> + '_ {
        self.sources.iter()
    }

    pub fn labels(&self) -> impl Iterator<Item = &str> + '_ {
        self.sources.iter().map(ChangeSource::label)
    }

    pub fn contains(&self, label: impl AsRef<str>) -> bool {
        let label = label.as_ref();
        self.sources.iter().any(|source| source.label() == label)
    }

    pub fn includes(&self, category: ChangeCategory) -> bool {
        self.sources
            .iter()
            .any(|source| source.category() == category)
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    pub fn merge(&mut self, other: &ChangeProvenance) {
        for source in &other.sources {
            if !self.sources.contains(source) {
                self.sources.push(source.clone());
            }
        }
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
    pub struct ChangeKinds: u32 {
        const BYTES_WRITTEN           = 0x0000_0001;
        const FUNCTION_ADDED          = 0x0000_0002;
        const FUNCTION_CHANGED        = 0x0000_0004;
        const FUNCTION_PROPERTIES     = 0x0004_0000;
        const FUNCTION_REMOVED        = 0x0000_0008;
        const LIFTED_MATERIALISED     = 0x0000_0010;
        const LIFTED_REMOVED          = 0x0000_0020;
        const PROBLEM_RECORDED        = 0x0010_0000;
        const PROBLEM_RESOLVED        = 0x0020_0000;
        const REFERENCE_ADDED         = 0x0000_0040;
        const REFERENCE_REMOVED       = 0x0000_0080;
        const RESYNCHRONISE           = 0x0000_0100;
        const SEGMENT_MAPPED          = 0x0000_0200;
        const SEGMENT_MAPPING_CHANGED = 0x0000_0400;
        const SEGMENT_MAPPING_CREATED = 0x0000_0800;
        const SEGMENT_UNMAPPED        = 0x0000_1000;
        const SPACE_CREATED           = 0x0000_2000;
        const SWITCH_ADDED            = 0x0000_4000;
        const SWITCH_REMOVED          = 0x0000_8000;
        const SYMBOL_ADDED            = 0x0001_0000;
        const SYMBOL_CHANGED          = 0x0008_0000;
        const SYMBOL_REMOVED          = 0x0002_0000;

        const FUNCTIONS = Self::FUNCTION_ADDED.bits()
            | Self::FUNCTION_CHANGED.bits()
            | Self::FUNCTION_PROPERTIES.bits()
            | Self::FUNCTION_REMOVED.bits();
        const LIFTED = Self::LIFTED_MATERIALISED.bits()
            | Self::LIFTED_REMOVED.bits();
        const PROBLEMS = Self::PROBLEM_RECORDED.bits() | Self::PROBLEM_RESOLVED.bits();
        const REFERENCES = Self::REFERENCE_ADDED.bits() | Self::REFERENCE_REMOVED.bits();
        const SEGMENTS = Self::SEGMENT_MAPPED.bits()
            | Self::SEGMENT_UNMAPPED.bits()
            | Self::SEGMENT_MAPPING_CREATED.bits()
            | Self::SEGMENT_MAPPING_CHANGED.bits();
        const SWITCHES = Self::SWITCH_ADDED.bits() | Self::SWITCH_REMOVED.bits();
        const SYMBOLS = Self::SYMBOL_ADDED.bits()
            | Self::SYMBOL_CHANGED.bits()
            | Self::SYMBOL_REMOVED.bits();
    }
}

impl ChangeKinds {
    pub(crate) fn for_problem(kind: ProblemKind) -> Self {
        let recovery = Self::BYTES_WRITTEN | Self::FUNCTIONS | Self::SEGMENTS | Self::SYMBOLS;
        match kind {
            ProblemKind::AvoidedBytes => Self::BYTES_WRITTEN | Self::SEGMENTS,
            ProblemKind::CannotCreateFunction
            | ProblemKind::DecodeFailed
            | ProblemKind::FunctionTooLarge
            | ProblemKind::PassFailed => recovery,
            ProblemKind::HinderedByAssertedFact => Self::FUNCTIONS,
            ProblemKind::SwitchBoundExceeded | ProblemKind::SwitchUnresolved => {
                Self::BYTES_WRITTEN | Self::FUNCTIONS | Self::SEGMENTS | Self::SWITCHES
            }
            ProblemKind::Unknown => Self::all().difference(Self::PROBLEMS),
            ProblemKind::AnalysisCoverageInvalidated
            | ProblemKind::ChangeIndexCollapsed
            | ProblemKind::PendingWorkCollapsed
            | ProblemKind::ReadSetCollapsed
            | ProblemKind::RetryBudgetExhausted
            | ProblemKind::WorkCausesMerged => Self::empty(),
        }
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
    LiftedMaterialised {
        function: FunctionId,
        form: IlFormId,
    },
    LiftedRemoved {
        function: FunctionId,
        form: IlFormId,
    },
    ProblemRecorded {
        scope: ProblemScope,
        kind: ProblemKind,
    },
    ProblemResolved {
        scope: ProblemScope,
        kind: ProblemKind,
    },
    ReferenceAdded {
        from: Address,
        target: ReferenceTarget,
        kind: ReferenceKind,
    },
    ReferenceRemoved {
        from: Address,
        target: ReferenceTarget,
        kind: ReferenceKind,
    },
    ReferencesChanged {
        coverage: AddressRangeSet,
    },
    Resynchronise {
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
    SwitchAdded {
        branch: Address,
    },
    SwitchRemoved {
        branch: Address,
    },
    SymbolAdded {
        address: Address,
        symbol: Symbol,
    },
    SymbolChanged {
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
            Self::FunctionChanged {
                kind: FunctionChangeKind::Properties,
                ..
            } => ChangeKinds::FUNCTION_PROPERTIES,
            Self::FunctionChanged { .. } => ChangeKinds::FUNCTION_CHANGED,
            Self::FunctionRemoved { .. } => ChangeKinds::FUNCTION_REMOVED,
            Self::LiftedMaterialised { .. } => ChangeKinds::LIFTED_MATERIALISED,
            Self::LiftedRemoved { .. } => ChangeKinds::LIFTED_REMOVED,
            Self::ProblemRecorded { .. } => ChangeKinds::PROBLEM_RECORDED,
            Self::ProblemResolved { .. } => ChangeKinds::PROBLEM_RESOLVED,
            Self::ReferenceAdded { .. } => ChangeKinds::REFERENCE_ADDED,
            Self::ReferenceRemoved { .. } => ChangeKinds::REFERENCE_REMOVED,
            Self::ReferencesChanged { .. } => ChangeKinds::REFERENCES,
            Self::Resynchronise { .. } => ChangeKinds::RESYNCHRONISE,
            Self::SegmentMapped { .. } => ChangeKinds::SEGMENT_MAPPED,
            Self::SegmentMappingChanged { .. } => ChangeKinds::SEGMENT_MAPPING_CHANGED,
            Self::SegmentMappingCreated { .. } => ChangeKinds::SEGMENT_MAPPING_CREATED,
            Self::SegmentUnmapped { .. } => ChangeKinds::SEGMENT_UNMAPPED,
            Self::SpaceCreated { .. } => ChangeKinds::SPACE_CREATED,
            Self::SwitchAdded { .. } => ChangeKinds::SWITCH_ADDED,
            Self::SwitchRemoved { .. } => ChangeKinds::SWITCH_REMOVED,
            Self::SymbolAdded { .. } => ChangeKinds::SYMBOL_ADDED,
            Self::SymbolChanged { .. } => ChangeKinds::SYMBOL_CHANGED,
            Self::SymbolRemoved { .. } => ChangeKinds::SYMBOL_REMOVED,
        }
    }

    pub fn affects_lifted_inputs(&self) -> bool {
        !matches!(
            self,
            Self::LiftedMaterialised { .. }
                | Self::LiftedRemoved { .. }
                | Self::ReferencesChanged { .. }
                | Self::ReferenceAdded { .. }
                | Self::ReferenceRemoved { .. }
                | Self::SymbolAdded { .. }
                | Self::SymbolChanged { .. }
                | Self::SymbolRemoved { .. }
                | Self::SwitchAdded { .. }
                | Self::SwitchRemoved { .. }
                | Self::ProblemRecorded { .. }
                | Self::ProblemResolved { .. }
                | Self::FunctionChanged {
                    kind: FunctionChangeKind::Properties,
                    ..
                }
        )
    }

    pub fn ranges(&self) -> SmallVec<[AddressRange; 4]> {
        match self {
            Self::BytesWritten { range }
            | Self::SegmentMapped { range, .. }
            | Self::SegmentUnmapped { range, .. } => [*range].into_iter().collect(),
            Self::FunctionAdded { coverage, .. }
            | Self::FunctionChanged { coverage, .. }
            | Self::FunctionRemoved { coverage, .. } => coverage.ranges().collect(),
            Self::SymbolAdded { address, .. }
            | Self::SymbolChanged { address, .. }
            | Self::SymbolRemoved { address, .. } => {
                [AddressRange::point(*address)].into_iter().collect()
            }
            Self::SwitchAdded { branch } | Self::SwitchRemoved { branch } => {
                [AddressRange::point(*branch)].into_iter().collect()
            }
            Self::ProblemRecorded { scope, .. } | Self::ProblemResolved { scope, .. } => {
                scope.range().into_iter().collect()
            }
            Self::ReferenceAdded { from, target, .. }
            | Self::ReferenceRemoved { from, target, .. } => {
                let mut ranges = SmallVec::new();
                ranges.push(AddressRange::point(*from));
                if let Some(address) = target.address() {
                    ranges.push(AddressRange::point(address));
                }
                ranges
            }
            Self::ReferencesChanged { coverage } => coverage.ranges().collect(),
            Self::Resynchronise { .. }
            | Self::LiftedMaterialised { .. }
            | Self::LiftedRemoved { .. }
            | Self::SegmentMappingChanged { .. }
            | Self::SegmentMappingCreated { .. }
            | Self::SpaceCreated { .. } => SmallVec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSet {
    revision: Revision,
    records: Arc<Vec<ChangeRecord>>,
    kinds: ChangeKinds,
    provenance: ChangeProvenance,
}

impl ChangeSet {
    pub fn new(revision: Revision) -> Self {
        Self {
            revision,
            records: Arc::new(Vec::new()),
            kinds: ChangeKinds::empty(),
            provenance: ChangeProvenance::empty(),
        }
    }

    pub fn with_records(revision: Revision, records: impl Into<Vec<ChangeRecord>>) -> Self {
        let records = records.into();
        let kinds = records
            .iter()
            .fold(ChangeKinds::empty(), |kinds, record| kinds | record.kind());
        Self {
            revision,
            records: Arc::new(records),
            kinds,
            provenance: ChangeProvenance::empty(),
        }
    }

    pub fn set_provenance(&mut self, source: impl Into<ChangeSource>) {
        self.provenance = ChangeProvenance::of(source);
    }

    pub fn with_provenance(mut self, source: impl Into<ChangeSource>) -> Self {
        self.set_provenance(source);
        self
    }

    pub fn provenance(&self) -> &ChangeProvenance {
        &self.provenance
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

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn contains(&self, kinds: ChangeKinds) -> bool {
        self.kinds.intersects(kinds)
    }

    pub fn push(&mut self, record: ChangeRecord) {
        self.kinds |= record.kind();
        Arc::make_mut(&mut self.records).push(record);
    }

    pub fn merge(&mut self, other: &ChangeSet) {
        self.revision = self.revision.max(other.revision);
        self.kinds |= other.kinds;
        Arc::make_mut(&mut self.records).extend(other.records.iter().cloned());
        self.provenance.merge(&other.provenance);
    }

    pub(crate) fn merge_provenance(&mut self, provenance: &ChangeProvenance) {
        self.provenance.merge(provenance);
    }
}
