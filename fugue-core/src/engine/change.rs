use smallvec::SmallVec;
use smol_str::SmolStr;

use crate::il::common::IrLevel;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, ReferenceKind, ReferenceTarget, Symbol,
};
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;

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
pub struct ChangeSourceFilter {
    categories: SmallVec<[ChangeCategory; 4]>,
    labels: SmallVec<[SmolStr; 2]>,
}

impl ChangeSourceFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn category(mut self, category: ChangeCategory) -> Self {
        if !self.categories.contains(&category) {
            self.categories.push(category);
        }
        self
    }

    pub fn label(mut self, label: impl Into<SmolStr>) -> Self {
        let label = label.into();
        if !self.labels.contains(&label) {
            self.labels.push(label);
        }
        self
    }

    pub fn is_empty(&self) -> bool {
        self.categories.is_empty() && self.labels.is_empty()
    }

    pub fn matches(&self, provenance: &ChangeProvenance) -> bool {
        if self.is_empty() {
            return true;
        }

        provenance.sources().any(|source| {
            (self.categories.is_empty() || self.categories.contains(&source.category()))
                && (self.labels.is_empty()
                    || self.labels.iter().any(|label| label == source.label()))
        })
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
        const REFERENCE_ADDED         = 0x1000;
        const REFERENCE_REMOVED       = 0x2000;
        const IR_ARTEFACT_PUBLISHED   = 0x4000;
        const IR_ARTEFACT_REMOVED     = 0x8000;

        const FUNCTIONS = Self::FUNCTION_ADDED.bits()
            | Self::FUNCTION_CHANGED.bits()
            | Self::FUNCTION_REMOVED.bits();
        const SYMBOLS = Self::SYMBOL_ADDED.bits() | Self::SYMBOL_REMOVED.bits();
        const SEGMENTS = Self::SEGMENT_MAPPED.bits()
            | Self::SEGMENT_UNMAPPED.bits()
            | Self::SEGMENT_MAPPING_CREATED.bits()
            | Self::SEGMENT_MAPPING_CHANGED.bits();
        const REFERENCES = Self::REFERENCE_ADDED.bits() | Self::REFERENCE_REMOVED.bits();
        const IR_ARTEFACTS = Self::IR_ARTEFACT_PUBLISHED.bits()
            | Self::IR_ARTEFACT_REMOVED.bits();
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
    IrArtefactPublished {
        function: FunctionId,
        level: IrLevel,
    },
    IrArtefactRemoved {
        function: FunctionId,
        level: IrLevel,
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
            Self::ReferenceAdded { .. } => ChangeKinds::REFERENCE_ADDED,
            Self::ReferenceRemoved { .. } => ChangeKinds::REFERENCE_REMOVED,
            Self::ReferencesChanged { .. } => ChangeKinds::REFERENCES,
            Self::IrArtefactPublished { .. } => ChangeKinds::IR_ARTEFACT_PUBLISHED,
            Self::IrArtefactRemoved { .. } => ChangeKinds::IR_ARTEFACT_REMOVED,
        }
    }

    pub fn affects_ir_inputs(&self) -> bool {
        !matches!(
            self,
            Self::IrArtefactPublished { .. }
                | Self::IrArtefactRemoved { .. }
                | Self::ReferencesChanged { .. }
                | Self::ReferenceAdded { .. }
                | Self::ReferenceRemoved { .. }
                | Self::SymbolAdded { .. }
                | Self::SymbolRemoved { .. }
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
            Self::SymbolAdded { address, .. } | Self::SymbolRemoved { address, .. } => {
                [AddressRange::point(*address)].into_iter().collect()
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
            Self::Restored { .. }
            | Self::IrArtefactPublished { .. }
            | Self::IrArtefactRemoved { .. }
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
    provenance: ChangeProvenance,
}

impl ChangeSet {
    pub fn new(revision: Revision) -> Self {
        Self {
            revision,
            records: Vec::new(),
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
            records,
            kinds,
            provenance: ChangeProvenance::empty(),
        }
    }

    pub fn attributed_to(mut self, source: impl Into<ChangeSource>) -> Self {
        self.provenance = ChangeProvenance::of(source);
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

    pub fn merge(&mut self, other: &ChangeSet) {
        self.revision = self.revision.max(other.revision);
        self.kinds |= other.kinds;
        self.records.extend(other.records.iter().cloned());
        self.provenance.merge(&other.provenance);
    }

    pub fn scoped_to(&self, filter: &ChangeFilter) -> Option<ChangeSet> {
        if !filter.sources().matches(&self.provenance) {
            return None;
        }

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
            let mut scoped_set = Self::with_records(self.revision, scoped);
            scoped_set.provenance = self.provenance.clone();
            Some(scoped_set)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeFilter {
    kinds: ChangeKinds,
    region: Option<AddressRangeSet>,
    sources: ChangeSourceFilter,
}

impl Default for ChangeFilter {
    fn default() -> Self {
        Self {
            kinds: ChangeKinds::all(),
            region: None,
            sources: ChangeSourceFilter::new(),
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

    pub fn with_category(mut self, category: ChangeCategory) -> Self {
        self.sources = self.sources.category(category);
        self
    }

    pub fn with_source_label(mut self, label: impl Into<SmolStr>) -> Self {
        self.sources = self.sources.label(label);
        self
    }

    pub fn kinds(&self) -> ChangeKinds {
        self.kinds
    }

    pub fn region(&self) -> Option<&AddressRangeSet> {
        self.region.as_ref()
    }

    pub fn sources(&self) -> &ChangeSourceFilter {
        &self.sources
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
    fn test_change_set_provenance_attribution_and_merge() {
        let mut merged = ChangeSet::with_records(Revision::new(1), [function_record(0x1000)])
            .attributed_to(ChangeSource::agent("update"));
        assert!(merged.provenance().contains("update"));
        assert!(merged.provenance().includes(ChangeCategory::Agent));
        assert!(!merged.provenance().includes(ChangeCategory::Analysis));

        let analysis = ChangeSet::with_records(Revision::new(2), [function_record(0x2000)])
            .attributed_to(ChangeSource::analysis("function-recovery"));
        merged.merge(&analysis);
        assert!(merged.provenance().contains("update"));
        assert!(merged.provenance().contains("function-recovery"));
        assert!(merged.provenance().includes(ChangeCategory::Analysis));

        let repeat = ChangeSet::with_records(Revision::new(3), [function_record(0x3000)])
            .attributed_to(ChangeSource::agent("update"));
        merged.merge(&repeat);
        assert_eq!(merged.provenance().sources().count(), 2);
        assert_eq!(
            merged.provenance().labels().collect::<Vec<_>>(),
            ["update", "function-recovery"]
        );

        let unlabelled = ChangeSet::with_records(Revision::new(4), [function_record(0x4000)])
            .attributed_to("external tool");
        assert!(unlabelled.provenance().includes(ChangeCategory::Other));
        assert!(!unlabelled.provenance().includes(ChangeCategory::Agent));
    }

    #[test]
    fn test_change_source_filter_selects_by_category_and_label() {
        let agent = ChangeSet::with_records(Revision::new(1), [function_record(0x1000)])
            .attributed_to(ChangeSource::agent("update"));
        let analysis = ChangeSet::with_records(Revision::new(2), [function_record(0x2000)])
            .attributed_to(ChangeSource::analysis("function-recovery"));
        let mut mixed = agent.clone();
        mixed.merge(&analysis);

        let analysis_only = ChangeFilter::new().with_category(ChangeCategory::Analysis);
        assert!(agent.scoped_to(&analysis_only).is_none());
        assert!(analysis.scoped_to(&analysis_only).is_some());
        assert!(mixed.scoped_to(&analysis_only).is_some());

        let recovery_only = ChangeFilter::new().with_source_label("function-recovery");
        assert!(agent.scoped_to(&recovery_only).is_none());
        assert!(analysis.scoped_to(&recovery_only).is_some());

        let agent_recovery = ChangeFilter::new()
            .with_category(ChangeCategory::Agent)
            .with_source_label("function-recovery");
        assert!(analysis.scoped_to(&agent_recovery).is_none());
        assert!(mixed.scoped_to(&agent_recovery).is_none());

        let unattributed = ChangeSet::with_records(Revision::new(3), [function_record(0x3000)]);
        assert!(unattributed.scoped_to(&analysis_only).is_none());
        assert!(unattributed.scoped_to(&ChangeFilter::new()).is_some());
    }

    #[test]
    fn test_change_set_scoping_preserves_provenance() {
        let changes = ChangeSet::with_records(
            Revision::new(1),
            [function_record(0x1000), bytes_record(0x2000, 0x2fff)],
        )
        .attributed_to(ChangeSource::analysis("function-recovery"));

        let filter = ChangeFilter::new().with_kinds(ChangeKinds::FUNCTIONS);
        let scoped = changes.scoped_to(&filter).expect("scoped set missing");

        assert_eq!(scoped.len(), 1);
        assert!(scoped.provenance().contains("function-recovery"));
        assert!(scoped.provenance().includes(ChangeCategory::Analysis));
    }

    #[test]
    fn test_change_set_merge_unions_kinds_and_concatenates_records() {
        let mut merged = ChangeSet::with_records(Revision::new(3), [function_record(0x1000)]);
        let other = ChangeSet::with_records(
            Revision::new(5),
            [bytes_record(0x2000, 0x2fff), function_record(0x3000)],
        );

        merged.merge(&other);

        assert_eq!(merged.revision(), Revision::new(5));
        assert_eq!(merged.kinds(), other.kinds() | ChangeKinds::FUNCTION_ADDED);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged.records()[0], function_record(0x1000));
        assert_eq!(merged.records()[1..], *other.records());

        let mut newer = ChangeSet::with_records(Revision::new(9), [function_record(0x4000)]);
        newer.merge(&merged);
        assert_eq!(newer.revision(), Revision::new(9));
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
