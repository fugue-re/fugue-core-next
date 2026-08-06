use std::collections::{BTreeMap, BTreeSet};
use std::iter;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use super::{ProjectTransaction, StagedReferenceRecord};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, Reference, ReferenceIndex, ReferenceKey, ReferenceKind,
    ReferenceOrigin, ReferenceTarget,
};
use crate::project::ProjectError;

pub(crate) struct DerivedReferenceBatch {
    coverage: AddressRangeSet,
    kind: ReferenceKind,
    references: Vec<Reference>,
}

impl DerivedReferenceBatch {
    pub(crate) fn new(
        coverage: AddressRangeSet,
        kind: ReferenceKind,
        references: impl IntoIterator<Item = Reference>,
    ) -> Self {
        Self {
            coverage,
            kind,
            references: references
                .into_iter()
                .map(|reference| reference.with_origin(ReferenceOrigin::Derived))
                .collect(),
        }
    }
}

impl ProjectTransaction<'_> {
    pub(crate) fn replace_derived_references(
        &mut self,
        coverage: AddressRangeSet,
        kind: ReferenceKind,
        derived: impl IntoIterator<Item = Reference>,
    ) -> Result<bool, ProjectError> {
        self.replace_derived_reference_batches(iter::once(DerivedReferenceBatch::new(
            coverage, kind, derived,
        )))
    }

    pub(crate) fn replace_derived_reference_batches(
        &mut self,
        replacements: impl IntoIterator<Item = DerivedReferenceBatch>,
    ) -> Result<bool, ProjectError> {
        let mut replacements = replacements.into_iter().collect::<SmallVec<[_; 4]>>();
        let mut combined_coverage = AddressRangeSet::new();
        for replacement in &mut replacements {
            for reference in &replacement.references {
                replacement
                    .coverage
                    .insert_range(AddressRange::point(reference.from()));
            }
            for range in replacement.coverage.ranges() {
                combined_coverage.insert_range(range);
            }
        }
        if combined_coverage.is_empty() {
            return Ok(false);
        }

        let mut current = self
            .staged_references_in(&combined_coverage)?
            .into_iter()
            .map(|reference| {
                (
                    ReferenceKey::new(reference.from(), reference.target()),
                    reference,
                )
            })
            .collect::<BTreeMap<_, _>>();
        if current.is_empty() {
            let mut changed = false;
            for replacement in replacements {
                if replacement.references.is_empty() {
                    continue;
                }
                for reference in replacement.references {
                    let key = ReferenceKey::new(reference.from(), reference.target());
                    self.stage_reference_record(key, None, Some(reference));
                }
                for range in replacement.coverage.ranges() {
                    self.derived_reference_coverage.insert_range(range);
                }
                changed = true;
            }
            return Ok(changed);
        }

        let flow_reference_count = replacements
            .iter()
            .filter(|replacement| replacement.kind.is_flow())
            .map(|replacement| replacement.references.len())
            .sum();
        let mut supported_flow = FxHashMap::<ReferenceKey, Reference>::with_capacity_and_hasher(
            flow_reference_count,
            Default::default(),
        );
        for replacement in &replacements {
            if !replacement.kind.is_flow() {
                continue;
            }
            for &reference in &replacement.references {
                let key = ReferenceKey::new(reference.from(), reference.target());
                supported_flow
                    .entry(key)
                    .and_modify(|supported| {
                        *supported = supported.with_merged_properties(reference.properties());
                    })
                    .or_insert(reference);
            }
        }

        let mut changed = false;

        for replacement in replacements {
            let mut covered = Vec::new();
            for range in replacement.coverage.ranges() {
                let start = ReferenceKey::minimum_for(range.start_address());
                for (&key, &reference) in current.range(start..) {
                    if key.from() > range.end_address() {
                        break;
                    }
                    covered.push(reference);
                }
            }
            if covered.is_empty() {
                if replacement.references.is_empty() {
                    continue;
                }
                for reference in replacement.references {
                    let key = ReferenceKey::new(reference.from(), reference.target());
                    current.insert(key, reference);
                    self.stage_reference_record(key, None, Some(reference));
                }
                for range in replacement.coverage.ranges() {
                    self.derived_reference_coverage.insert_range(range);
                }
                changed = true;
                continue;
            }
            if ReferenceIndex::derived_kind_matches(
                &covered,
                &replacement.references,
                replacement.kind,
            ) {
                continue;
            }

            let mut occupied = BTreeSet::new();
            for reference in covered {
                let key = ReferenceKey::new(reference.from(), reference.target());
                if reference.origin().is_derived() && reference.kind() == replacement.kind {
                    let supported = match supported_flow.get(&key) {
                        Some(&supported) => Some(supported),
                        None if replacement.kind.is_flow() => {
                            self.function_staging.supported_backing_flow_reference(
                                &self.project.functions,
                                &self.project.blocks,
                                reference,
                            )?
                        }
                        None => None,
                    };
                    if let Some(supported) = supported {
                        current.insert(key, supported);
                        if supported != reference {
                            self.stage_reference_record(key, Some(reference), Some(supported));
                        }
                        continue;
                    }
                    current.remove(&key);
                    self.stage_reference_record(key, Some(reference), None);
                } else {
                    occupied.insert(key);
                }
            }
            for reference in replacement.references {
                let key = ReferenceKey::new(reference.from(), reference.target());
                if !occupied.contains(&key) {
                    current.insert(key, reference);
                    self.stage_reference_record(key, None, Some(reference));
                }
            }

            for range in replacement.coverage.ranges() {
                self.derived_reference_coverage.insert_range(range);
            }
            changed = true;
        }

        Ok(changed)
    }

    pub fn add_reference(&mut self, reference: Reference) -> Result<bool, ProjectError> {
        let reference = reference.with_origin(ReferenceOrigin::Asserted);
        let from = reference.from();
        let target = reference.target();

        let key = ReferenceKey::new(from, target);
        let existing = self.staged_reference(key)?;
        let resolved = match existing {
            Some(existing)
                if existing.origin().is_asserted() && existing.kind() == reference.kind() =>
            {
                existing.with_merged_properties(reference.properties())
            }
            _ => reference,
        };

        if let Some(existing) = existing
            && existing.origin().is_asserted()
            && existing.kind() == resolved.kind()
            && existing.properties() == resolved.properties()
        {
            return Ok(false);
        }

        self.stage_reference_record(key, existing, Some(resolved));
        self.asserted_references.insert(key);
        Ok(true)
    }

    pub fn remove_reference(
        &mut self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<bool, ProjectError> {
        let key = ReferenceKey::new(from, target);
        let Some(previous) = self.staged_reference(key)? else {
            return Ok(false);
        };

        self.stage_reference_record(key, Some(previous), None);
        self.asserted_references.insert(key);
        Ok(true)
    }

    fn stage_reference_record(
        &mut self,
        key: ReferenceKey,
        previous: Option<Reference>,
        reference: Option<Reference>,
    ) {
        if let Some(record) = self.staged_references.get_mut(&key) {
            record.reference = reference;
        } else {
            self.staged_references.insert(
                key,
                StagedReferenceRecord {
                    previous,
                    reference,
                },
            );
        }
    }

    fn staged_reference(&self, key: ReferenceKey) -> Result<Option<Reference>, ProjectError> {
        match self.staged_references.get(&key) {
            Some(record) => Ok(record.reference),
            None => self
                .project
                .references
                .get(key.from(), key.target())
                .map_err(ProjectError::from),
        }
    }

    fn staged_references_in(
        &self,
        coverage: &AddressRangeSet,
    ) -> Result<Vec<Reference>, ProjectError> {
        let mut references = self
            .project
            .references
            .references_in(coverage)?
            .into_iter()
            .map(|reference| {
                (
                    ReferenceKey::new(reference.from(), reference.target()),
                    reference,
                )
            })
            .collect::<BTreeMap<_, _>>();
        for range in coverage.ranges() {
            let start = ReferenceKey::minimum_for(range.start_address());
            for (&key, record) in self.staged_references.range(start..) {
                if key.from() > range.end_address() {
                    break;
                }
                match record.reference {
                    Some(reference) => {
                        references.insert(key, reference);
                    }
                    None => {
                        references.remove(&key);
                    }
                }
            }
        }
        Ok(references.into_values().collect())
    }
}
