use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::ir::reference::{
    Reference, ReferenceKey, ReferenceKind, ReferenceRecord, ReferenceTarget,
};
use crate::ir::{Address, AddressRange, AddressRangeSet, CodeBlockTable, FunctionRef};
use crate::storage::EntityStorage;
use crate::storage::entities::schema::ENTITY_KEY_REFERENCE_INVERSE_ID;
use crate::storage::entities::{
    Entity, EntityKey, EntityKeyCodec, EntityKeyId, EntityStorageError, EntityWrite,
    WriteBackWorker,
};
use crate::types::Revision;

mod persistent;
use persistent::ReferenceIndex as PersistentReferenceIndex;

mod transient;
use transient::ReferenceIndex as TransientReferenceIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InverseReferenceKey {
    target: ReferenceTarget,
    from: Address,
}

impl InverseReferenceKey {
    fn new(target: ReferenceTarget, from: Address) -> Self {
        Self { target, from }
    }

    fn minimum_for(target: ReferenceTarget) -> Self {
        Self::new(target, Address::MINIMUM)
    }

    fn from(&self) -> Address {
        self.from
    }

    fn target(&self) -> ReferenceTarget {
        self.target
    }
}

impl EntityKeyCodec for InverseReferenceKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let target = ReferenceTarget::decode(input)?;
        let from = Address::decode(input)?;
        Some(Self { target, from })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.target.encode(output);
        self.from.encode(output);
    }
}

impl EntityKey for InverseReferenceKey {
    const ID: EntityKeyId = ENTITY_KEY_REFERENCE_INVERSE_ID;
}

pub enum ReferenceIndex {
    Persistent(PersistentReferenceIndex),
    Transient(TransientReferenceIndex),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PreparedReferenceIndexRecord {
    encoded_size: usize,
    key: ReferenceKey,
    reference: Option<Reference>,
}

impl PreparedReferenceIndexRecord {
    pub(crate) fn new(
        key: ReferenceKey,
        reference: Option<Reference>,
        encoded_size: usize,
    ) -> Self {
        Self {
            encoded_size,
            key,
            reference,
        }
    }

    pub(crate) fn key(&self) -> ReferenceKey {
        self.key
    }

    pub(crate) fn reference(&self) -> Option<Reference> {
        self.reference
    }
}

impl ReferenceIndex {
    pub(crate) fn new_transient() -> Self {
        Self::Transient(TransientReferenceIndex::default())
    }

    pub(crate) fn new(
        storage: EntityStorage,
        worker: Option<Arc<WriteBackWorker>>,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Persistent(PersistentReferenceIndex::new(
            storage, worker,
        )?))
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }

    pub(crate) fn get(
        &self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<Option<Reference>, EntityStorageError> {
        match self {
            Self::Persistent(index) => index.get(from, target),
            Self::Transient(index) => Ok(index.get(from, target)),
        }
    }

    pub(crate) fn references_from(
        &self,
        from: Address,
        after: Option<&Reference>,
    ) -> Result<
        Box<dyn Iterator<Item = Result<Reference, EntityStorageError>> + '_>,
        EntityStorageError,
    > {
        match self {
            Self::Persistent(index) => Ok(Box::new(index.references_from(from, after)?)),
            Self::Transient(index) => Ok(Box::new(index.references_from(from, after))),
        }
    }

    pub(crate) fn references_to(
        &self,
        target: ReferenceTarget,
        after: Option<&Reference>,
    ) -> Result<
        Box<dyn Iterator<Item = Result<Reference, EntityStorageError>> + '_>,
        EntityStorageError,
    > {
        match self {
            Self::Persistent(index) => Ok(Box::new(index.references_to(target, after)?)),
            Self::Transient(index) => Ok(Box::new(index.references_to(target, after))),
        }
    }

    pub(crate) fn references_in(
        &self,
        coverage: &AddressRangeSet,
    ) -> Result<Vec<Reference>, EntityStorageError> {
        let mut references = Vec::new();
        for range in coverage.ranges() {
            self.collect_range(range, &mut references)?;
        }
        Ok(references)
    }

    pub(crate) fn insert(&mut self, reference: &Reference) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(index) => index.insert(reference),
            Self::Transient(index) => {
                index.insert(*reference);
                Ok(())
            }
        }
    }

    pub(crate) fn remove(
        &mut self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<(), EntityStorageError> {
        match self {
            Self::Persistent(index) => index.remove(from, target),
            Self::Transient(index) => {
                index.remove(from, target);
                Ok(())
            }
        }
    }

    pub(crate) fn prepare_record(
        key: ReferenceKey,
        reference: Option<Reference>,
    ) -> Result<(PreparedReferenceIndexRecord, [EntityWrite; 2]), EntityStorageError> {
        let forward = ReferenceRecord::ID.key_for(&key);
        let inverse_key = InverseReferenceKey::new(key.target(), key.from());
        let inverse = ReferenceRecord::ID.key_for(&inverse_key);
        let Some(reference) = reference else {
            return Ok((
                PreparedReferenceIndexRecord::new(key, None, 0),
                [EntityWrite::remove(forward), EntityWrite::remove(inverse)],
            ));
        };

        let record = ReferenceRecord::of(&reference);
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(&record).map_err(EntityStorageError::encode)?;
        let encoded = bytes::Bytes::from_owner(encoded);
        let encoded_size = encoded.len();
        Ok((
            PreparedReferenceIndexRecord::new(key, Some(reference), encoded_size),
            [
                EntityWrite::insert(forward, encoded.clone()),
                EntityWrite::insert(inverse, encoded),
            ],
        ))
    }

    pub(crate) fn publish_records(
        &mut self,
        records: impl IntoIterator<Item = PreparedReferenceIndexRecord>,
    ) {
        match self {
            Self::Persistent(index) => index.publish_records(records),
            Self::Transient(index) => index.publish_records(records),
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

    pub(crate) fn derived_kind_matches(
        current: &[Reference],
        derived: &[Reference],
        kind: ReferenceKind,
    ) -> bool {
        let mut occupied = FxHashSet::default();
        let mut existing = FxHashMap::default();
        for reference in current {
            let key = ReferenceKey::new(reference.from(), reference.target());
            if reference.origin().is_derived() && reference.kind() == kind {
                existing.insert(key, reference.properties());
            } else {
                occupied.insert(key);
            }
        }

        let mut desired = FxHashMap::default();
        for reference in derived {
            let key = ReferenceKey::new(reference.from(), reference.target());
            if !occupied.contains(&key) {
                desired.insert(key, reference.properties());
            }
        }

        existing == desired
    }

    fn rebuild<'a>(
        &mut self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
    ) -> Result<(), EntityStorageError> {
        let asserted = self.clear_derived()?;

        for function in functions {
            for reference in function.flow_references(blocks) {
                let key = ReferenceKey::new(reference.from(), reference.target());
                if !asserted.contains(&key) {
                    self.insert(&reference)?;
                }
            }
        }

        Ok(())
    }

    fn clear_derived(&mut self) -> Result<FxHashSet<ReferenceKey>, EntityStorageError> {
        let mut asserted = FxHashSet::default();
        let mut cursor = None;

        loop {
            let batch = match &mut *self {
                Self::Persistent(index) => index.origins_after(cursor.as_ref())?,
                Self::Transient(index) => return Ok(index.clear_derived()),
            };
            let Some((last, _)) = batch.last() else {
                break;
            };
            cursor = Some(*last);

            for (key, origin) in batch {
                if origin.is_derived() {
                    self.remove(key.from(), key.target())?;
                } else {
                    asserted.insert(key);
                }
            }
        }

        Ok(asserted)
    }

    fn collect_range(
        &self,
        range: AddressRange,
        references: &mut Vec<Reference>,
    ) -> Result<(), EntityStorageError> {
        let end = range.end_address();
        let start = ReferenceKey::minimum_for(range.start_address());
        match self {
            Self::Persistent(index) => index.collect_range(&start, end, references),
            Self::Transient(index) => {
                index.collect_range(&start, end, references);
                Ok(())
            }
        }
    }
}
