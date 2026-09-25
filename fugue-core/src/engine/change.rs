use smallvec::SmallVec;
use smol_str::SmolStr;

use crate::ir::AddressRangeSet;
use crate::project::{ChangeCategory, ChangeKinds, ChangeProvenance, ChangeRecord, ChangeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSourceFilter {
    categories: SmallVec<[ChangeCategory; 4]>,
    labels: SmallVec<[SmolStr; 2]>,
}

impl ChangeSourceFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_category(mut self, category: ChangeCategory) -> Self {
        if !self.categories.contains(&category) {
            self.categories.push(category);
        }
        self
    }

    pub fn with_label(mut self, label: impl Into<SmolStr>) -> Self {
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

    pub fn kinds(&self) -> ChangeKinds {
        self.kinds
    }

    pub fn set_kinds(&mut self, kinds: ChangeKinds) {
        self.kinds = kinds;
    }

    pub fn with_kinds(mut self, kinds: ChangeKinds) -> Self {
        self.set_kinds(kinds);
        self
    }

    pub fn region(&self) -> Option<&AddressRangeSet> {
        self.region.as_ref()
    }

    pub fn set_region(&mut self, region: AddressRangeSet) {
        self.region = Some(region);
    }

    pub fn with_region(mut self, region: AddressRangeSet) -> Self {
        self.set_region(region);
        self
    }

    pub fn sources(&self) -> &ChangeSourceFilter {
        &self.sources
    }

    pub fn with_category(mut self, category: ChangeCategory) -> Self {
        self.sources = self.sources.with_category(category);
        self
    }

    pub fn with_source_label(mut self, label: impl Into<SmolStr>) -> Self {
        self.sources = self.sources.with_label(label);
        self
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

    pub fn apply(&self, changes: &ChangeSet) -> Option<ChangeSet> {
        if !self.sources.matches(changes.provenance()) || !changes.contains(self.kinds) {
            return None;
        }

        let scoped = changes
            .records()
            .iter()
            .filter(|record| self.matches(record))
            .cloned()
            .collect::<Vec<_>>();

        if scoped.is_empty() {
            None
        } else {
            let mut scoped_set = ChangeSet::with_records(changes.revision(), scoped);
            scoped_set.merge_provenance(changes.provenance());
            Some(scoped_set)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::{Address, AddressRange, ProblemKind, ProblemScope, RawAddress};
    use crate::project::{ChangeRecord, ChangeSource, FunctionChangeKind};
    use crate::storage::segments::space::AddressSpaceId;
    use crate::types::Revision;

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
    fn change_kinds_composites_equal_union() {
        assert_eq!(
            ChangeKinds::FUNCTIONS,
            ChangeKinds::FUNCTION_ADDED
                | ChangeKinds::FUNCTION_CHANGED
                | ChangeKinds::FUNCTION_PROPERTIES
                | ChangeKinds::FUNCTION_REMOVED
        );
        assert_eq!(
            ChangeKinds::SYMBOLS,
            ChangeKinds::SYMBOL_ADDED | ChangeKinds::SYMBOL_CHANGED | ChangeKinds::SYMBOL_REMOVED
        );
    }

    #[test]
    fn change_set_provenance_attribution_and_merge() {
        let mut merged = ChangeSet::with_records(Revision::new(1), [function_record(0x1000)])
            .with_provenance(ChangeSource::agent("update"));
        let analysis = ChangeSet::with_records(Revision::new(2), [function_record(0x2000)])
            .with_provenance(ChangeSource::analysis("function-recovery"));

        merged.merge(&analysis);

        assert!(merged.provenance().contains("update"));
        assert!(merged.provenance().contains("function-recovery"));
        assert!(merged.provenance().includes(ChangeCategory::Agent));
        assert!(merged.provenance().includes(ChangeCategory::Analysis));
    }

    #[test]
    fn change_source_filter_selects_by_category_and_label() {
        let agent = ChangeSet::with_records(Revision::new(1), [function_record(0x1000)])
            .with_provenance(ChangeSource::agent("update"));
        let analysis = ChangeSet::with_records(Revision::new(2), [function_record(0x2000)])
            .with_provenance(ChangeSource::analysis("function-recovery"));
        let mut mixed = agent.clone();
        mixed.merge(&analysis);

        let analysis_only = ChangeFilter::new().with_category(ChangeCategory::Analysis);
        assert!(analysis_only.apply(&agent).is_none());
        assert!(analysis_only.apply(&analysis).is_some());
        assert!(analysis_only.apply(&mixed).is_some());

        let recovery_only = ChangeFilter::new().with_source_label("function-recovery");
        assert!(recovery_only.apply(&agent).is_none());
        assert!(recovery_only.apply(&analysis).is_some());
    }

    #[test]
    fn property_changes_do_not_stale_lifted_artefacts() {
        let entry = Address::from(0x1000u64);
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(entry));
        let properties = ChangeRecord::FunctionChanged {
            entry,
            kind: FunctionChangeKind::Properties,
            coverage,
        };
        let recorded = ChangeRecord::ProblemRecorded {
            scope: ProblemScope::Address(entry),
            kind: ProblemKind::DecodeFailed,
        };

        assert_eq!(properties.kind(), ChangeKinds::FUNCTION_PROPERTIES);
        assert!(!properties.affects_lifted_inputs());
        assert!(!recorded.affects_lifted_inputs());
        assert_eq!(recorded.ranges().len(), 1);
    }

    #[test]
    fn record_ranges_report_locality() {
        assert_eq!(
            bytes_record(0x2000, 0x2fff).ranges().as_slice(),
            &[AddressRange::new(
                AddressSpaceId::from(0u8),
                RawAddress::from(0x2000u64),
                RawAddress::from(0x2fffu64)
            )]
        );
    }
}
