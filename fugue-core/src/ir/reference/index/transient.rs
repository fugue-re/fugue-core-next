use std::collections::BTreeMap;
use std::ops::Bound;

use rustc_hash::FxHashSet;

use super::{InverseReferenceKey, PreparedReferenceIndexRecord};
use crate::ir::Address;
use crate::ir::reference::{
    Reference, ReferenceEntry, ReferenceKey, ReferenceKind, ReferenceTarget,
};
use crate::storage::entities::EntityStorageError;

pub struct ReferenceIndex {
    forward: BTreeMap<ReferenceKey, ReferenceEntry>,
    inverse: BTreeMap<InverseReferenceKey, ReferenceEntry>,
}

impl Default for ReferenceIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferenceIndex {
    pub(crate) fn new() -> Self {
        Self {
            forward: BTreeMap::new(),
            inverse: BTreeMap::new(),
        }
    }

    pub(crate) fn get(&self, key: ReferenceKey) -> Option<ReferenceEntry> {
        self.forward.get(&key).cloned()
    }

    pub(crate) fn references_from(
        &self,
        from: Address,
        after: Option<ReferenceKey>,
    ) -> impl Iterator<Item = Result<Reference, EntityStorageError>> + '_ {
        let start = after.map_or_else(
            || {
                Bound::Included(ReferenceKey::new(
                    from,
                    ReferenceTarget::minimum(),
                    ReferenceKind::Flow,
                ))
            },
            Bound::Excluded,
        );
        self.forward
            .range((start, Bound::Unbounded))
            .take_while(move |(key, _)| key.from() == from)
            .map(|(key, entry)| {
                Ok(entry
                    .materialise(*key)
                    .expect("stored reference entry must contain a visible reference"))
            })
    }

    pub(crate) fn references_to(
        &self,
        target: ReferenceTarget,
        after: Option<ReferenceKey>,
    ) -> impl Iterator<Item = Result<Reference, EntityStorageError>> + '_ {
        let start = after.map_or_else(
            || {
                Bound::Included(InverseReferenceKey::new(
                    target,
                    Address::MINIMUM,
                    ReferenceKind::Flow,
                ))
            },
            |after| {
                Bound::Excluded(InverseReferenceKey::new(
                    after.target(),
                    after.from(),
                    after.kind(),
                ))
            },
        );
        self.inverse
            .range((start, Bound::Unbounded))
            .take_while(move |(key, _)| key.target() == target)
            .map(|(key, entry)| {
                Ok(entry
                    .materialise(ReferenceKey::new(key.from(), key.target(), key.kind()))
                    .expect("stored reference entry must contain a visible reference"))
            })
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
                .map(|(key, entry)| {
                    entry
                        .materialise(*key)
                        .expect("stored reference entry must contain a visible reference")
                }),
        );
    }

    pub(crate) fn insert(&mut self, key: ReferenceKey, entry: ReferenceEntry) {
        let inverse = InverseReferenceKey::new(key.target(), key.from(), key.kind());
        self.forward.insert(key, entry.clone());
        self.inverse.insert(inverse, entry);
    }

    pub(crate) fn remove(&mut self, key: ReferenceKey) {
        self.forward.remove(&key);
        self.inverse.remove(&InverseReferenceKey::new(
            key.target(),
            key.from(),
            key.kind(),
        ));
    }

    pub(crate) fn clear_derived(&mut self) -> FxHashSet<ReferenceKey> {
        let mut asserted = FxHashSet::default();
        let mut asserted_entries = self
            .forward
            .iter()
            .filter_map(|(&key, entry)| {
                let mut entry = entry.clone();
                entry.clear_derived();
                (!entry.is_empty()).then_some((key, entry))
            })
            .collect::<Vec<_>>();
        self.forward.clear();
        self.inverse.clear();
        for (key, entry) in asserted_entries.drain(..) {
            asserted.insert(key);
            self.insert(key, entry);
        }
        asserted
    }

    pub(crate) fn publish_batch(
        &mut self,
        records: impl IntoIterator<Item = PreparedReferenceIndexRecord>,
    ) {
        for record in records {
            let PreparedReferenceIndexRecord { entry, key, .. } = record;
            match entry {
                Some(entry) => self.insert(key, entry),
                None => self.remove(key),
            }
        }
    }
}
