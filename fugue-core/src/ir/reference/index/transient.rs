use std::collections::BTreeMap;
use std::ops::Bound;

use rustc_hash::FxHashSet;

use super::{InverseReferenceKey, PreparedReferenceIndexRecord};
use crate::ir::Address;
use crate::ir::reference::{Reference, ReferenceKey, ReferenceTarget};
use crate::storage::entities::EntityStorageError;

#[derive(Default)]
pub struct ReferenceIndex {
    forward: BTreeMap<ReferenceKey, Reference>,
    inverse: BTreeMap<InverseReferenceKey, Reference>,
}

impl ReferenceIndex {
    pub(crate) fn get(&self, from: Address, target: ReferenceTarget) -> Option<Reference> {
        self.forward.get(&ReferenceKey::new(from, target)).copied()
    }

    pub(crate) fn references_from(
        &self,
        from: Address,
        after: Option<&Reference>,
    ) -> impl Iterator<Item = Result<Reference, EntityStorageError>> + '_ {
        let start = after.map_or_else(
            || Bound::Included(ReferenceKey::minimum_for(from)),
            |after| Bound::Excluded(ReferenceKey::new(after.from(), after.target())),
        );
        self.forward
            .range((start, Bound::Unbounded))
            .take_while(move |(key, _)| key.from() == from)
            .map(|(_, &reference)| Ok(reference))
    }

    pub(crate) fn references_to(
        &self,
        target: ReferenceTarget,
        after: Option<&Reference>,
    ) -> impl Iterator<Item = Result<Reference, EntityStorageError>> + '_ {
        let start = after.map_or_else(
            || Bound::Included(InverseReferenceKey::minimum_for(target)),
            |after| Bound::Excluded(InverseReferenceKey::new(after.target(), after.from())),
        );
        self.inverse
            .range((start, Bound::Unbounded))
            .take_while(move |(key, _)| key.target() == target)
            .map(|(_, &reference)| Ok(reference))
    }

    pub(crate) fn collect_range(
        &self,
        start: &ReferenceKey,
        end: Address,
        references: &mut Vec<Reference>,
    ) {
        references.extend(
            self.forward
                .range((Bound::Included(*start), Bound::Unbounded))
                .take_while(|(key, _)| key.from() <= end)
                .map(|(_, reference)| *reference),
        );
    }

    pub(crate) fn insert(&mut self, reference: Reference) {
        let forward = ReferenceKey::new(reference.from(), reference.target());
        let inverse = InverseReferenceKey::new(reference.target(), reference.from());
        self.forward.insert(forward, reference);
        self.inverse.insert(inverse, reference);
    }

    pub(crate) fn remove(&mut self, from: Address, target: ReferenceTarget) {
        self.forward.remove(&ReferenceKey::new(from, target));
        self.inverse.remove(&InverseReferenceKey::new(target, from));
    }

    pub(crate) fn publish_records(
        &mut self,
        records: impl IntoIterator<Item = PreparedReferenceIndexRecord>,
    ) {
        for record in records {
            let PreparedReferenceIndexRecord { key, reference, .. } = record;
            match reference {
                Some(reference) => self.insert(reference),
                None => self.remove(key.from(), key.target()),
            }
        }
    }

    pub(crate) fn clear_derived(&mut self) -> FxHashSet<ReferenceKey> {
        let mut asserted = FxHashSet::default();
        let asserted_references = self
            .forward
            .values()
            .filter(|reference| !reference.origin().is_derived())
            .copied()
            .collect::<Vec<_>>();
        self.forward.clear();
        self.inverse.clear();
        for reference in asserted_references {
            asserted.insert(ReferenceKey::new(reference.from(), reference.target()));
            self.insert(reference);
        }
        asserted
    }
}
