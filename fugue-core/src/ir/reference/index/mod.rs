use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rustc_hash::FxHashSet;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::reference::{
    Reference, ReferenceKey, ReferenceKind, ReferenceOrigin, ReferenceProperties,
    ReferenceProvenance, ReferenceTarget,
};
use crate::ir::{Address, AddressRange, AddressRangeSet, CodeBlockTable, FunctionRef};
use crate::storage::EntityStorage;
use crate::storage::entities::schema::{
    ENTITY_KEY_REFERENCE_INVERSE_ID, ENTITY_REFERENCE_ENTRY_ID,
};
use crate::storage::entities::{
    Entity, EntityId, EntityKey, EntityKeyCodec, EntityKeyId, EntityStorageError, EntityWriteBatch,
    WriteBackWorker,
};
use crate::types::Revision;

mod persistent;
use persistent::ReferenceIndex as PersistentReferenceIndex;

mod transient;
use transient::ReferenceIndex as TransientReferenceIndex;

pub(crate) const ATTRIBUTE_REFERENCE_INDEX_CACHE_SIZE: &str =
    "storage.entities.reference.index.cache_size";
pub(crate) const DEFAULT_REFERENCE_INDEX_CACHE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct InverseReferenceKey {
    target: ReferenceTarget,
    from: Address,
    kind: ReferenceKind,
}

impl InverseReferenceKey {
    fn new(target: ReferenceTarget, from: Address, kind: ReferenceKind) -> Self {
        Self { target, from, kind }
    }

    fn from(&self) -> Address {
        self.from
    }

    fn target(&self) -> ReferenceTarget {
        self.target
    }

    fn kind(&self) -> ReferenceKind {
        self.kind
    }
}

impl EntityKeyCodec for InverseReferenceKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let target = ReferenceTarget::decode(input)?;
        let from = Address::decode(input)?;
        let kind = ReferenceKind::decode(input)?;
        Some(Self::new(target, from, kind))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.target.encode(output);
        self.from.encode(output);
        self.kind.encode(output);
    }
}

impl EntityKey for InverseReferenceKey {
    const ID: EntityKeyId = ENTITY_KEY_REFERENCE_INVERSE_ID;
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct ReferenceEntry {
    provenances: SmallVec<[(ReferenceProvenance, ReferenceProperties); 1]>,
}

impl ReferenceEntry {
    pub(crate) fn new(provenance: ReferenceProvenance, properties: ReferenceProperties) -> Self {
        Self {
            provenances: SmallVec::from_buf([(provenance, properties)]),
        }
    }

    fn set_provenance(
        &mut self,
        provenance: ReferenceProvenance,
        properties: Option<ReferenceProperties>,
    ) {
        match (
            self.provenances
                .binary_search_by_key(&provenance, |entry| entry.0),
            properties,
        ) {
            (Ok(index), Some(properties)) => self.provenances[index].1 = properties,
            (Ok(index), None) => {
                self.provenances.remove(index);
            }
            (Err(index), Some(properties)) => {
                self.provenances.insert(index, (provenance, properties));
            }
            (Err(_), None) => {}
        }
    }

    fn has_provenance(&self, provenance: ReferenceProvenance) -> bool {
        self.provenances
            .binary_search_by_key(&provenance, |entry| entry.0)
            .is_ok()
    }

    fn is_empty(&self) -> bool {
        self.provenances.is_empty()
    }

    pub(crate) fn merge_provenance(
        &mut self,
        provenance: ReferenceProvenance,
        properties: ReferenceProperties,
    ) {
        let properties = self
            .provenances
            .binary_search_by_key(&provenance, |entry| entry.0)
            .map_or(properties, |index| self.provenances[index].1 | properties);
        self.set_provenance(provenance, Some(properties));
    }

    fn clear_derived(&mut self) {
        self.provenances
            .retain(|entry| entry.0 == ReferenceProvenance::Asserted);
    }

    pub(crate) fn materialise(&self, key: ReferenceKey) -> Option<Reference> {
        let first = self.provenances.first()?;
        if first.0 == ReferenceProvenance::Asserted {
            return Some(Reference::new(
                key.from(),
                key.target(),
                key.kind(),
                first.1,
            ));
        }

        let properties = match self.provenances.as_slice() {
            [(_, properties)] => *properties,
            provenances => provenances
                .iter()
                .map(|entry| entry.1)
                .fold(ReferenceProperties::empty(), |merged, properties| {
                    merged | properties
                }),
        };
        Some(
            Reference::new(key.from(), key.target(), key.kind(), properties)
                .with_origin(ReferenceOrigin::Derived),
        )
    }
}

impl Entity for ReferenceEntry {
    const ID: EntityId = ENTITY_REFERENCE_ENTRY_ID;
}

pub enum ReferenceIndex {
    Persistent(PersistentReferenceIndex),
    Transient(TransientReferenceIndex),
}

pub type ReferenceIterator<'a> =
    Box<dyn Iterator<Item = Result<Reference, EntityStorageError>> + 'a>;

#[derive(Debug, Error)]
pub enum ReferenceIndexError {
    #[error("derived reference insertion requires provenance")]
    MissingProvenance,
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

pub(crate) struct DerivedReferenceBatch {
    coverage: AddressRangeSet,
    kind: ReferenceKind,
    provenance: ReferenceProvenance,
    references: Vec<Reference>,
}

impl DerivedReferenceBatch {
    pub(crate) fn new(
        mut coverage: AddressRangeSet,
        kind: ReferenceKind,
        provenance: ReferenceProvenance,
        references: impl IntoIterator<Item = Reference>,
    ) -> Self {
        let mut references = references
            .into_iter()
            .map(|reference| reference.with_origin(ReferenceOrigin::Derived))
            .collect::<Vec<_>>();
        references.sort_unstable_by_key(Reference::key);
        references.dedup_by(|next, current| {
            if next.key() != current.key() {
                return false;
            }
            *current = current.with_merged_properties(next.properties());
            true
        });
        debug_assert!(references.iter().all(|reference| reference.kind() == kind));
        for reference in &references {
            coverage.insert_range(AddressRange::point(reference.from()));
        }

        Self {
            coverage,
            kind,
            provenance,
            references,
        }
    }
}

#[derive(Default)]
pub(crate) struct ReferenceStaging {
    asserted: BTreeSet<ReferenceKey>,
    derived_coverage: AddressRangeSet,
    staged_references: BTreeMap<ReferenceKey, StagedReferenceRecord>,
}

#[derive(Clone)]
struct StagedReferenceRecord {
    previous: Option<ReferenceEntry>,
    entry: Option<ReferenceEntry>,
}

pub(crate) struct PreparedReferenceBatch {
    asserted: BTreeSet<ReferenceKey>,
    derived_coverage: AddressRangeSet,
    records: Vec<PreparedReferenceIndexRecord>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedReferenceIndexRecord {
    encoded_size: usize,
    entry: Option<ReferenceEntry>,
    key: ReferenceKey,
}

impl PreparedReferenceIndexRecord {
    fn new(key: ReferenceKey, entry: Option<ReferenceEntry>, encoded_size: usize) -> Self {
        Self {
            encoded_size,
            entry,
            key,
        }
    }
}

impl ReferenceStaging {
    pub(crate) fn insert(
        &mut self,
        index: &ReferenceIndex,
        reference: Reference,
    ) -> Result<bool, EntityStorageError> {
        let key = reference.key();
        let existing = self.entry(index, key)?;
        let mut entry = existing.clone().unwrap_or_else(|| {
            ReferenceEntry::new(ReferenceProvenance::Asserted, reference.properties())
        });
        entry.merge_provenance(ReferenceProvenance::Asserted, reference.properties());
        if existing.as_ref() == Some(&entry) {
            return Ok(false);
        }

        self.stage_change(key, existing, Some(entry));
        self.asserted.insert(key);
        Ok(true)
    }

    pub(crate) fn remove(
        &mut self,
        index: &ReferenceIndex,
        key: ReferenceKey,
    ) -> Result<bool, EntityStorageError> {
        let Some(mut entry) = self.entry(index, key)? else {
            return Ok(false);
        };
        if !entry.has_provenance(ReferenceProvenance::Asserted) {
            return Ok(false);
        }

        let previous = entry.clone();
        entry.set_provenance(ReferenceProvenance::Asserted, None);
        let entry = (!entry.is_empty()).then_some(entry);
        self.stage_change(key, Some(previous), entry);
        self.asserted.insert(key);
        Ok(true)
    }

    pub(crate) fn replace_derived_reference_batches(
        &mut self,
        index: &ReferenceIndex,
        batches: impl IntoIterator<Item = DerivedReferenceBatch>,
    ) -> Result<bool, EntityStorageError> {
        let batches = batches.into_iter().collect::<Vec<_>>();
        let mut combined_coverage = AddressRangeSet::new();
        for batch in &batches {
            for range in batch.coverage.ranges() {
                combined_coverage.insert_range(range);
            }
        }
        if combined_coverage.is_empty() {
            return Ok(false);
        }

        let mut current = self.references_in(index, &combined_coverage)?;
        let mut covered = Vec::new();
        let mut changed = false;
        for batch in batches {
            covered.clear();
            for range in batch.coverage.ranges() {
                let start = ReferenceKey::new(
                    range.start_address(),
                    ReferenceTarget::minimum(),
                    ReferenceKind::Flow,
                );
                for (&key, _) in current.range(start..) {
                    if key.from() > range.end_address() {
                        break;
                    }
                    covered.push(key);
                }
            }

            let mut batch_changed = false;
            for key in covered.drain(..) {
                let previous = current
                    .get(&key)
                    .cloned()
                    .expect("covered reference key must exist");
                if key.kind() != batch.kind {
                    continue;
                }

                let mut entry = previous.clone();
                let properties = batch
                    .references
                    .binary_search_by_key(&key, Reference::key)
                    .ok()
                    .map(|index| batch.references[index].properties());
                entry.set_provenance(batch.provenance, properties);
                let entry = (!entry.is_empty()).then_some(entry);
                if entry.as_ref() == Some(&previous) {
                    continue;
                }
                match &entry {
                    Some(entry) => {
                        current.insert(key, entry.clone());
                    }
                    None => {
                        current.remove(&key);
                    }
                }
                self.stage_change(key, Some(previous), entry);
                batch_changed = true;
            }

            for reference in batch.references {
                let key = reference.key();
                if current.contains_key(&key) {
                    continue;
                }
                let entry = ReferenceEntry::new(batch.provenance, reference.properties());
                current.insert(key, entry.clone());
                self.stage_change(key, None, Some(entry));
                batch_changed = true;
            }

            if batch_changed {
                for range in batch.coverage.ranges() {
                    self.derived_coverage.insert_range(range);
                }
            }
            changed |= batch_changed;
        }

        Ok(changed)
    }

    pub(crate) fn prepare(
        self,
        index: &ReferenceIndex,
    ) -> Result<(PreparedReferenceBatch, EntityWriteBatch), EntityStorageError> {
        let Self {
            asserted,
            derived_coverage,
            staged_references,
        } = self;
        let mut prepared = Vec::with_capacity(staged_references.len());
        for (key, staged) in staged_references {
            if staged.entry == staged.previous {
                continue;
            }
            prepared.push(PreparedReferenceIndexRecord::new(key, staged.entry, 0));
        }

        let mut writes = EntityWriteBatch::with_capacity(prepared.len().saturating_mul(2));
        index.append_prepared_writes(&mut prepared, &mut writes)?;
        Ok((
            PreparedReferenceBatch {
                asserted,
                derived_coverage,
                records: prepared,
            },
            writes,
        ))
    }

    fn entry(
        &self,
        index: &ReferenceIndex,
        key: ReferenceKey,
    ) -> Result<Option<ReferenceEntry>, EntityStorageError> {
        match self.staged_references.get(&key) {
            Some(staged) => Ok(staged.entry.clone()),
            None => match index {
                ReferenceIndex::Persistent(index) => index.try_get(key),
                ReferenceIndex::Transient(index) => Ok(index.get(key)),
            },
        }
    }

    fn references_in(
        &self,
        index: &ReferenceIndex,
        coverage: &AddressRangeSet,
    ) -> Result<BTreeMap<ReferenceKey, ReferenceEntry>, EntityStorageError> {
        let references = index.references_in(coverage)?.into_iter();
        let mut entries = BTreeMap::new();
        for reference in references {
            let key = reference.key();
            if let Some(entry) = self.entry(index, key)? {
                entries.insert(key, entry);
            }
        }
        for range in coverage.ranges() {
            let start = ReferenceKey::new(
                range.start_address(),
                ReferenceTarget::minimum(),
                ReferenceKind::Flow,
            );
            for (&key, staged) in self.staged_references.range(start..) {
                if key.from() > range.end_address() {
                    break;
                }
                match &staged.entry {
                    Some(entry) => {
                        entries.insert(key, entry.clone());
                    }
                    None => {
                        entries.remove(&key);
                    }
                }
            }
        }
        Ok(entries)
    }

    fn stage_change(
        &mut self,
        key: ReferenceKey,
        previous: Option<ReferenceEntry>,
        entry: Option<ReferenceEntry>,
    ) {
        if let Some(staged) = self.staged_references.get_mut(&key) {
            staged.entry = entry;
        } else {
            self.staged_references
                .insert(key, StagedReferenceRecord { previous, entry });
        }
    }
}

impl ReferenceIndex {
    pub fn new_transient() -> Self {
        Self::Transient(TransientReferenceIndex::new())
    }

    pub fn new_persistent(
        storage: EntityStorage,
        cache_bytes: usize,
        worker: Arc<WriteBackWorker>,
    ) -> Self {
        Self::Persistent(PersistentReferenceIndex::new(storage, cache_bytes, worker))
    }

    pub fn get(&self, key: ReferenceKey) -> Result<Option<Reference>, EntityStorageError> {
        let entry = match self {
            Self::Persistent(index) => index.try_get(key)?,
            Self::Transient(index) => index.get(key),
        };
        Ok(entry.and_then(|entry| entry.materialise(key)))
    }

    pub fn references_from(
        &self,
        from: Address,
        after: Option<ReferenceKey>,
    ) -> Result<ReferenceIterator<'_>, EntityStorageError> {
        match self {
            Self::Persistent(index) => Ok(Box::new(index.references_from(from, after)?)),
            Self::Transient(index) => Ok(Box::new(index.references_from(from, after))),
        }
    }

    pub fn references_to(
        &self,
        target: ReferenceTarget,
        after: Option<ReferenceKey>,
    ) -> Result<ReferenceIterator<'_>, EntityStorageError> {
        match self {
            Self::Persistent(index) => Ok(Box::new(index.references_to(target, after)?)),
            Self::Transient(index) => Ok(Box::new(index.references_to(target, after))),
        }
    }

    pub fn references_in(
        &self,
        coverage: &AddressRangeSet,
    ) -> Result<Vec<Reference>, EntityStorageError> {
        let mut references = Vec::new();
        for range in coverage.ranges() {
            self.collect_range(range, &mut references)?;
        }
        Ok(references)
    }

    pub fn insert(&mut self, reference: &Reference) -> Result<(), ReferenceIndexError> {
        if reference.origin().is_derived() {
            return Err(ReferenceIndexError::MissingProvenance);
        }
        self.merge_provenance(reference, ReferenceProvenance::Asserted)?;
        Ok(())
    }

    pub fn remove(&mut self, key: ReferenceKey) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(index) => index.remove(key),
            Self::Transient(index) => {
                index.remove(key);
                Ok(())
            }
        }
    }

    pub(crate) fn ensure_current<'a>(
        &mut self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
        revision: Revision,
    ) -> Result<(), EntityStorageError> {
        if let Self::Persistent(index) = self
            && index.metadata_revision()? == Some(revision)
        {
            return Ok(());
        }

        self.rebuild(functions, blocks)?;
        if let Self::Persistent(index) = self {
            index.flush()?;
        }
        self.mark_current(revision)
    }

    pub(crate) fn mark_current(&self, revision: Revision) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(index) => index.mark_current(revision),
            Self::Transient(_) => Ok(()),
        }
    }

    fn rebuild<'a>(
        &mut self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
    ) -> Result<(), EntityStorageError> {
        let asserted = self.clear_derived()?;

        for function in functions {
            let provenance = ReferenceProvenance::Function(function.id());
            for reference in function.flow_references(blocks) {
                let key = reference.key();
                if !asserted.contains(&key) {
                    self.merge_provenance(&reference, provenance)?;
                }
            }
        }

        Ok(())
    }

    fn clear_derived(&mut self) -> Result<FxHashSet<ReferenceKey>, EntityStorageError> {
        match self {
            Self::Persistent(index) => index.clear_derived(),
            Self::Transient(index) => Ok(index.clear_derived()),
        }
    }

    fn merge_provenance(
        &mut self,
        reference: &Reference,
        provenance: ReferenceProvenance,
    ) -> Result<(), EntityStorageError> {
        let key = reference.key();
        match self {
            Self::Persistent(index) => {
                let mut entry = index
                    .try_get(key)?
                    .unwrap_or_else(|| ReferenceEntry::new(provenance, reference.properties()));
                entry.merge_provenance(provenance, reference.properties());
                index.insert(key, &entry)
            }
            Self::Transient(index) => {
                let mut entry = index
                    .get(key)
                    .unwrap_or_else(|| ReferenceEntry::new(provenance, reference.properties()));
                entry.merge_provenance(provenance, reference.properties());
                index.insert(key, entry);
                Ok(())
            }
        }
    }

    fn collect_range(
        &self,
        range: AddressRange,
        references: &mut Vec<Reference>,
    ) -> Result<(), EntityStorageError> {
        let end = range.end_address();
        let start = ReferenceKey::new(
            range.start_address(),
            ReferenceTarget::minimum(),
            ReferenceKind::Flow,
        );
        match self {
            Self::Persistent(index) => index.collect_range(&start, end, references),
            Self::Transient(index) => {
                index.collect_range(&start, end, references);
                Ok(())
            }
        }
    }

    fn append_prepared_writes(
        &self,
        records: &mut [PreparedReferenceIndexRecord],
        writes: &mut EntityWriteBatch,
    ) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(_) => persistent::append_prepared_writes(records, writes),
            Self::Transient(_) => Ok(()),
        }
    }
}

impl PreparedReferenceBatch {
    pub(crate) fn asserted_changes(&self) -> impl Iterator<Item = (ReferenceKey, bool)> + '_ {
        self.records
            .iter()
            .filter(|record| self.asserted.contains(&record.key))
            .map(|record| {
                let present = record
                    .entry
                    .as_ref()
                    .and_then(|entry| entry.materialise(record.key))
                    .is_some();
                (record.key, present)
            })
    }

    pub(crate) fn derived_coverage(&self) -> &AddressRangeSet {
        &self.derived_coverage
    }

    pub(crate) fn derived_changed(&self) -> bool {
        self.records
            .iter()
            .any(|record| self.derived_coverage.contains(record.key.from()))
    }

    pub(crate) fn publish(self, index: &mut ReferenceIndex) {
        match index {
            ReferenceIndex::Persistent(index) => index.publish_batch(self.records),
            ReferenceIndex::Transient(index) => index.publish_batch(self.records),
        }
    }
}
