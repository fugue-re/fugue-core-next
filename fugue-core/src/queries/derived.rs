use crate::engine::change::{ChangeKinds, Revision};
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
        F: FnOnce(&QueryReader) -> Result<T, QueryError>,
    {
        let latest = self.dependency.latest(reader)?;

        match &self.value {
            Some(value) if self.watermark == Some(latest) => Ok(value.clone()),
            _ => {
                let value = compute(reader)?;
                self.value = Some(value.clone());
                self.watermark = Some(latest);
                Ok(value)
            }
        }
    }
}
