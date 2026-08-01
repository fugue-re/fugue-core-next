use crate::engine::change::{ChangeKinds, Revision};
use crate::engine::{ProjectView, ReadSet};
use crate::ir::AddressRangeSet;
use crate::queries::{QueryError, QueryReader};

struct DependencyClause {
    kinds: ChangeKinds,
    region: AddressRangeSet,
}

pub struct Dependency {
    clauses: Vec<DependencyClause>,
}

impl Dependency {
    pub fn on(kinds: ChangeKinds) -> Self {
        Self {
            clauses: vec![DependencyClause {
                kinds,
                region: AddressRangeSet::new(),
            }],
        }
    }

    pub fn within(mut self, region: AddressRangeSet) -> Self {
        if let Some(clause) = self.clauses.last_mut() {
            clause.region = region;
        }
        self
    }

    pub fn and(mut self, other: Dependency) -> Self {
        self.clauses.extend(other.clauses);
        self
    }

    pub fn covers(&self, reads: &ReadSet) -> bool {
        reads.observed().iter().all(|kind| {
            self.clauses.iter().any(|clause| {
                clause.kinds.contains(kind)
                    && (clause.region.is_empty() || !reads.escapes(kind, &clause.region))
            })
        })
    }

    pub fn latest(&self, reader: &QueryReader) -> Result<Revision, QueryError> {
        let mut latest = Revision::new(0);
        for clause in &self.clauses {
            latest = latest.max(reader.latest_change(clause.kinds, &clause.region)?);
        }
        Ok(latest)
    }
}

pub struct Cached<T> {
    dependency: Dependency,
    watermark: Option<Revision>,
    value: Option<T>,
}

impl<T> Cached<T>
where
    T: Clone,
{
    pub fn new(dependency: Dependency) -> Self {
        Self {
            dependency,
            watermark: None,
            value: None,
        }
    }

    pub fn get<F>(&mut self, reader: &QueryReader, compute: F) -> Result<T, QueryError>
    where
        F: FnOnce(&ProjectView<'_>) -> Result<T, QueryError>,
    {
        let latest = self.dependency.latest(reader)?;

        if let Some(value) = &self.value
            && self.watermark == Some(latest)
        {
            return Ok(value.clone());
        }

        let handle = reader.project()?;
        let view = ProjectView::new(&handle);
        let value = compute(&view)?;
        let reads = view.into_reads();

        if !self.dependency.covers(&reads) {
            return Err(QueryError::UndeclaredDependency(reads.observed()));
        }

        self.value = Some(value.clone());
        self.watermark = Some(latest);
        Ok(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::AddressRange;
    use crate::storage::segments::DEFAULT_SPACE_ID;

    fn region(start: u64, end: u64) -> AddressRangeSet {
        let mut set = AddressRangeSet::new();
        set.insert_range(AddressRange::new(
            DEFAULT_SPACE_ID,
            start.into(),
            end.into(),
        ));
        set
    }

    fn reads_of(kinds: ChangeKinds, start: u64, end: u64) -> ReadSet {
        let mut reads = ReadSet::new();
        reads.record(
            kinds,
            AddressRange::new(DEFAULT_SPACE_ID, start.into(), end.into()),
        );
        reads
    }

    #[test]
    fn a_declaration_covering_the_observed_reads_holds() {
        let declared = Dependency::on(ChangeKinds::FUNCTIONS).within(region(0x1000, 0x1fff));

        assert!(declared.covers(&reads_of(ChangeKinds::FUNCTIONS, 0x1200, 0x1300)));
    }

    #[test]
    fn a_declaration_missing_an_observed_kind_fails() {
        let declared = Dependency::on(ChangeKinds::FUNCTIONS);

        assert!(
            !declared.covers(&reads_of(ChangeKinds::SWITCHES, 0x1200, 0x1300)),
            "reading switches while declaring only functions must be reported"
        );
    }

    #[test]
    fn a_declaration_too_narrow_in_range_fails() {
        let declared = Dependency::on(ChangeKinds::FUNCTIONS).within(region(0x1000, 0x1fff));

        assert!(
            !declared.covers(&reads_of(ChangeKinds::FUNCTIONS, 0x1800, 0x2800)),
            "reading outside the declared region must be reported"
        );
    }

    #[test]
    fn an_unbounded_read_needs_an_unbounded_declaration() {
        let narrow = Dependency::on(ChangeKinds::FUNCTIONS).within(region(0x1000, 0x1fff));
        let wide = Dependency::on(ChangeKinds::FUNCTIONS);

        let mut reads = ReadSet::new();
        reads.record_unbounded(ChangeKinds::FUNCTIONS);

        assert!(!narrow.covers(&reads));
        assert!(wide.covers(&reads));
    }

    #[test]
    fn a_computation_reading_more_than_it_declares_is_rejected() {
        let declared = Dependency::on(ChangeKinds::FUNCTIONS);

        let mut reads = ReadSet::new();
        reads.record_unbounded(ChangeKinds::SYMBOLS);

        assert!(
            !declared.covers(&reads),
            "a cached computation that reads symbols while declaring only functions must be \
             rejected by `Cached::get` in every build"
        );
    }

    #[test]
    fn an_empty_read_set_is_covered_by_any_declaration() {
        let declared = Dependency::on(ChangeKinds::FUNCTIONS);

        assert!(declared.covers(&ReadSet::new()));
    }
}
