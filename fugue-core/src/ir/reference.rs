use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::ops::Bound;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::{ArcRwLockReadGuard, RawRwLock, RwLock};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::ir::cfg::FlowKind;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, CodeBlockTable, FunctionRef, IndexMetadata,
};
use crate::storage::EntityStorage;
use crate::storage::entities::schema::{
    ENTITY_KEY_REFERENCE_FORWARD_ID, ENTITY_KEY_REFERENCE_INVERSE_ID, ENTITY_REFERENCE_RECORD_ID,
};
use crate::storage::entities::{
    Entity, EntityCache, EntityId, EntityKey, EntityKeyCodec, EntityKeyId, EntityStorageError,
    EntityWrite, ProjectEntity, WriteBackWorker,
};
use crate::types::Revision;
use crate::types::common::{archived_bitflags, cursor_bound, cursor_bound_or_minimum};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[repr(u8)]
pub enum ReferenceKind {
    Flow = 0,
    Data = 1,
}

impl ReferenceKind {
    pub fn is_flow(self) -> bool {
        matches!(self, Self::Flow)
    }

    pub fn is_data(self) -> bool {
        matches!(self, Self::Data)
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
#[repr(u8)]
pub enum ReferenceOrigin {
    #[default]
    Derived = 0,
    Asserted = 1,
}

impl ReferenceOrigin {
    pub fn is_derived(self) -> bool {
        matches!(self, Self::Derived)
    }

    pub fn is_asserted(self) -> bool {
        matches!(self, Self::Asserted)
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ReferenceProperties: u16 {
        const CALL          = 0x0001;
        const JUMP          = 0x0002;
        const CONDITIONAL   = 0x0004;
        const COMPUTED      = 0x0008;
        const TERMINAL      = 0x0010;
        const FALL_THROUGH  = 0x0020;
        const OVERRIDE      = 0x0040;
        const READ          = 0x0080;
        const WRITE         = 0x0100;
        const INDIRECT      = 0x0200;
    }
}

archived_bitflags!(ReferenceProperties, ArchivedReferenceProperties, u16);

impl ReferenceProperties {
    pub fn from_flow(kind: FlowKind) -> Self {
        match kind {
            FlowKind::Branch => Self::JUMP,
            FlowKind::CBranch => Self::JUMP | Self::CONDITIONAL,
            FlowKind::IBranch => Self::JUMP | Self::COMPUTED,
            FlowKind::Fall => Self::FALL_THROUGH,
            FlowKind::Call => Self::CALL,
            FlowKind::ICall => Self::CALL | Self::COMPUTED,
            FlowKind::ServiceCall => Self::CALL,
            FlowKind::Return => Self::TERMINAL,
            FlowKind::SwitchBranch => Self::JUMP | Self::COMPUTED,
            FlowKind::SwitchCall => Self::CALL | Self::COMPUTED,
            FlowKind::TailCallBranch => Self::CALL | Self::JUMP | Self::TERMINAL,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReferenceTarget {
    Address(Address),
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum ReferenceTargetKind {
    Address,
}

impl ReferenceTarget {
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(address) => Some(*address),
        }
    }

    fn minimum() -> Self {
        Self::Address(Address::MINIMUM)
    }
}

impl EntityKeyCodec for ReferenceTarget {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let (&kind, rest) = input.split_first()?;
        *input = rest;
        match kind {
            kind if kind == ReferenceTargetKind::Address as u8 => {
                Address::decode(input).map(Self::Address)
            }
            _ => None,
        }
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        match self {
            Self::Address(address) => {
                output.extend([ReferenceTargetKind::Address as u8]);
                address.encode(output);
            }
        }
    }
}

impl From<Address> for ReferenceTarget {
    fn from(address: Address) -> Self {
        Self::Address(address)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Reference {
    from: Address,
    target: ReferenceTarget,
    kind: ReferenceKind,
    properties: ReferenceProperties,
    origin: ReferenceOrigin,
}

impl Reference {
    pub fn new(
        from: Address,
        target: impl Into<ReferenceTarget>,
        kind: ReferenceKind,
        properties: ReferenceProperties,
    ) -> Self {
        Self {
            from,
            target: target.into(),
            kind,
            properties,
            origin: ReferenceOrigin::Asserted,
        }
    }

    pub fn flow(
        from: Address,
        target: impl Into<ReferenceTarget>,
        properties: ReferenceProperties,
    ) -> Self {
        Self::new(from, target, ReferenceKind::Flow, properties)
    }

    pub fn data(
        from: Address,
        target: impl Into<ReferenceTarget>,
        properties: ReferenceProperties,
    ) -> Self {
        Self::new(from, target, ReferenceKind::Data, properties)
    }

    pub fn from_flow(from: Address, target: impl Into<ReferenceTarget>, kind: FlowKind) -> Self {
        Self::flow(from, target, ReferenceProperties::from_flow(kind))
    }

    pub fn with_origin(mut self, origin: ReferenceOrigin) -> Self {
        self.origin = origin;
        self
    }

    pub fn with_merged_properties(mut self, properties: ReferenceProperties) -> Self {
        self.properties |= properties;
        self
    }

    pub fn from(&self) -> Address {
        self.from
    }

    pub fn target(&self) -> ReferenceTarget {
        self.target
    }

    pub fn kind(&self) -> ReferenceKind {
        self.kind
    }

    pub fn properties(&self) -> ReferenceProperties {
        self.properties
    }

    pub fn origin(&self) -> ReferenceOrigin {
        self.origin
    }

    pub fn is_flow(&self) -> bool {
        self.kind.is_flow()
    }

    pub fn is_data(&self) -> bool {
        self.kind.is_data()
    }

    pub fn is_call(&self) -> bool {
        self.properties.contains(ReferenceProperties::CALL)
    }

    pub fn is_jump(&self) -> bool {
        self.properties.contains(ReferenceProperties::JUMP)
    }

    pub fn is_conditional(&self) -> bool {
        self.properties.contains(ReferenceProperties::CONDITIONAL)
    }

    pub fn is_computed(&self) -> bool {
        self.properties.contains(ReferenceProperties::COMPUTED)
    }

    pub fn is_terminal(&self) -> bool {
        self.properties.contains(ReferenceProperties::TERMINAL)
    }

    pub fn has_fall_through(&self) -> bool {
        self.properties.contains(ReferenceProperties::FALL_THROUGH)
    }

    pub fn is_read(&self) -> bool {
        self.properties.contains(ReferenceProperties::READ)
    }

    pub fn is_write(&self) -> bool {
        self.properties.contains(ReferenceProperties::WRITE)
    }

    pub fn is_indirect(&self) -> bool {
        self.properties.contains(ReferenceProperties::INDIRECT)
    }

    pub(crate) fn same_fact(&self, other: &Self) -> bool {
        self.from == other.from
            && self.target == other.target
            && self.kind == other.kind
            && self.properties == other.properties
            && self.origin == other.origin
    }
}

impl PartialEq for Reference {
    fn eq(&self, other: &Self) -> bool {
        self.from == other.from && self.target == other.target
    }
}

impl Eq for Reference {}

impl PartialOrd for Reference {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Reference {
    fn cmp(&self, other: &Self) -> Ordering {
        self.from
            .cmp(&other.from)
            .then_with(|| self.target.cmp(&other.target))
    }
}

impl Hash for Reference {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.from.hash(state);
        self.target.hash(state);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferenceKey {
    from: Address,
    target: ReferenceTarget,
}

impl ReferenceKey {
    pub fn new(from: Address, target: ReferenceTarget) -> Self {
        Self { from, target }
    }

    pub fn from(&self) -> Address {
        self.from
    }

    pub fn target(&self) -> ReferenceTarget {
        self.target
    }

    pub(crate) fn minimum_for(from: Address) -> Self {
        Self::new(from, ReferenceTarget::minimum())
    }
}

impl EntityKeyCodec for ReferenceKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let from = Address::decode(input)?;
        let target = ReferenceTarget::decode(input)?;
        Some(Self { from, target })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.from.encode(output);
        self.target.encode(output);
    }
}

impl EntityKey for ReferenceKey {
    const ID: EntityKeyId = ENTITY_KEY_REFERENCE_FORWARD_ID;
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ReferenceRecord {
    kind: ReferenceKind,
    properties: ReferenceProperties,
    origin: ReferenceOrigin,
}

impl ReferenceRecord {
    fn of(reference: &Reference) -> Self {
        Self {
            kind: reference.kind(),
            properties: reference.properties(),
            origin: reference.origin(),
        }
    }

    fn kind(&self) -> ReferenceKind {
        self.kind
    }

    fn properties(&self) -> ReferenceProperties {
        self.properties
    }

    fn origin(&self) -> ReferenceOrigin {
        self.origin
    }
}

impl Entity for ReferenceRecord {
    const ID: EntityId = ENTITY_REFERENCE_RECORD_ID;
}

#[derive(Clone)]
pub struct ReferenceIndex {
    backing: ReferenceIndexBacking,
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

#[derive(Clone)]
enum ReferenceIndexBacking {
    Persistent {
        forward: EntityCache<ReferenceKey, ReferenceRecord>,
        inverse: EntityCache<InverseReferenceKey, ReferenceRecord>,
        storage: EntityStorage,
    },
    Transient(Arc<RwLock<TransientReferenceIndex>>),
}

#[derive(Default)]
struct TransientReferenceIndex {
    forward: BTreeMap<ReferenceKey, Reference>,
    inverse: BTreeMap<InverseReferenceKey, Reference>,
}

struct PersistentReferenceIndex<'a> {
    forward: &'a EntityCache<ReferenceKey, ReferenceRecord>,
    inverse: &'a EntityCache<InverseReferenceKey, ReferenceRecord>,
    storage: &'a EntityStorage,
}

struct TransientReferencesFrom {
    index: ArcRwLockReadGuard<RawRwLock, TransientReferenceIndex>,
    from: Address,
    cursor: Option<ReferenceKey>,
}

impl Iterator for TransientReferencesFrom {
    type Item = Result<Reference, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.cursor.map_or_else(
            || Bound::Included(ReferenceKey::minimum_for(self.from)),
            Bound::Excluded,
        );
        let (&key, &reference) = self.index.forward.range((start, Bound::Unbounded)).next()?;
        if key.from() != self.from {
            return None;
        }
        self.cursor = Some(key);
        Some(Ok(reference))
    }
}

struct TransientReferencesTo {
    index: ArcRwLockReadGuard<RawRwLock, TransientReferenceIndex>,
    target: ReferenceTarget,
    cursor: Option<InverseReferenceKey>,
}

impl Iterator for TransientReferencesTo {
    type Item = Result<Reference, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.cursor.map_or_else(
            || Bound::Included(InverseReferenceKey::minimum_for(self.target)),
            Bound::Excluded,
        );
        let (&key, &reference) = self.index.inverse.range((start, Bound::Unbounded)).next()?;
        if key.target() != self.target {
            return None;
        }
        self.cursor = Some(key);
        Some(Ok(reference))
    }
}

impl TransientReferenceIndex {
    fn insert(&mut self, reference: Reference) {
        let forward = ReferenceKey::new(reference.from(), reference.target());
        let inverse = InverseReferenceKey::new(reference.target(), reference.from());
        self.forward.insert(forward, reference);
        self.inverse.insert(inverse, reference);
    }

    fn remove(&mut self, from: Address, target: ReferenceTarget) {
        self.forward.remove(&ReferenceKey::new(from, target));
        self.inverse.remove(&InverseReferenceKey::new(target, from));
    }
}

impl ReferenceIndex {
    const CACHE_BYTES: usize = 16 * 1024 * 1024;

    pub(crate) fn new_transient() -> Self {
        Self {
            backing: ReferenceIndexBacking::Transient(Arc::new(RwLock::new(
                TransientReferenceIndex::default(),
            ))),
        }
    }

    pub(crate) fn new(
        storage: EntityStorage,
        worker: Option<Arc<WriteBackWorker>>,
    ) -> Result<Self, EntityStorageError> {
        let forward =
            EntityCache::from_storage(storage.clone(), worker.clone(), Self::CACHE_BYTES)?;
        let inverse = EntityCache::from_storage(storage.clone(), worker, Self::CACHE_BYTES)?;

        Ok(Self {
            backing: ReferenceIndexBacking::Persistent {
                forward,
                inverse,
                storage,
            },
        })
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self.backing, ReferenceIndexBacking::Persistent { .. })
    }

    fn persistent(&self) -> Option<PersistentReferenceIndex<'_>> {
        match &self.backing {
            ReferenceIndexBacking::Persistent {
                forward,
                inverse,
                storage,
            } => Some(PersistentReferenceIndex {
                forward,
                inverse,
                storage,
            }),
            ReferenceIndexBacking::Transient(_) => None,
        }
    }
}

impl ReferenceIndex {
    pub(crate) fn insert(&self, reference: &Reference) -> Result<(), EntityStorageError> {
        let forward_key = ReferenceKey::new(reference.from(), reference.target());
        let inverse_key = InverseReferenceKey::new(reference.target(), reference.from());
        match &self.backing {
            ReferenceIndexBacking::Persistent {
                forward, inverse, ..
            } => {
                let record = ReferenceRecord::of(reference);
                forward.try_insert(forward_key, record)?;
                inverse.try_insert(inverse_key, record)?;
            }
            ReferenceIndexBacking::Transient(index) => {
                index.write().insert(*reference);
            }
        }
        Ok(())
    }

    pub(crate) fn remove(
        &self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<(), EntityStorageError> {
        let forward_key = ReferenceKey::new(from, target);
        let inverse_key = InverseReferenceKey::new(target, from);
        match &self.backing {
            ReferenceIndexBacking::Persistent {
                forward, inverse, ..
            } => {
                forward.try_remove(&forward_key)?;
                inverse.try_remove(&inverse_key)
            }
            ReferenceIndexBacking::Transient(index) => {
                index.write().remove(from, target);
                Ok(())
            }
        }
    }

    pub(crate) fn get(
        &self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<Option<Reference>, EntityStorageError> {
        let key = ReferenceKey::new(from, target);
        match &self.backing {
            ReferenceIndexBacking::Persistent { forward, .. } => {
                let Some(cached) = forward.try_get(&key)? else {
                    return Ok(None);
                };
                Ok(Some(Self::reference_from_record(
                    from,
                    target,
                    cached.as_ref(),
                )))
            }
            ReferenceIndexBacking::Transient(index) => Ok(index
                .read()
                .forward
                .get(&ReferenceKey::new(from, target))
                .copied()),
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
        let encoded = Bytes::from_owner(encoded);
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
        &self,
        records: impl IntoIterator<Item = PreparedReferenceIndexRecord>,
    ) {
        match &self.backing {
            ReferenceIndexBacking::Persistent {
                forward,
                inverse: inverse_index,
                ..
            } => {
                for record in records {
                    let PreparedReferenceIndexRecord {
                        encoded_size,
                        key,
                        reference,
                    } = record;
                    let inverse = InverseReferenceKey::new(key.target(), key.from());
                    match reference {
                        Some(reference) => {
                            let record = ReferenceRecord::of(&reference);
                            forward.publish_insert(key, record, encoded_size);
                            inverse_index.publish_insert(inverse, record, encoded_size);
                        }
                        None => {
                            forward.publish_remove(&key);
                            inverse_index.publish_remove(&inverse);
                        }
                    }
                }
            }
            ReferenceIndexBacking::Transient(index) => {
                let mut index = index.write();
                for record in records {
                    let PreparedReferenceIndexRecord { key, reference, .. } = record;
                    match reference {
                        Some(reference) => index.insert(reference),
                        None => index.remove(key.from(), key.target()),
                    }
                }
            }
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
        match &self.backing {
            ReferenceIndexBacking::Persistent { forward, .. } => {
                let after = after.map(|after| ReferenceKey::new(after.from(), after.target()));
                let start = cursor_bound_or_minimum(after, ReferenceKey::minimum_for(from));
                Ok(Box::new(
                    forward
                        .try_iter_range(start.as_ref())?
                        .take_while(move |result| {
                            result.as_ref().map_or(true, |(key, _)| key.from() == from)
                        })
                        .map(move |result| {
                            result.map(|(key, cached)| {
                                Self::reference_from_record(
                                    key.from(),
                                    key.target(),
                                    cached.as_ref(),
                                )
                            })
                        }),
                ))
            }
            ReferenceIndexBacking::Transient(index) => Ok(Box::new(TransientReferencesFrom {
                index: index.read_arc(),
                from,
                cursor: after.map(|after| ReferenceKey::new(after.from(), after.target())),
            })),
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
        match &self.backing {
            ReferenceIndexBacking::Persistent { inverse, .. } => {
                let after =
                    after.map(|after| InverseReferenceKey::new(after.target(), after.from()));
                let start =
                    cursor_bound_or_minimum(after, InverseReferenceKey::minimum_for(target));
                Ok(Box::new(
                    inverse
                        .try_iter_range(start.as_ref())?
                        .take_while(move |result| {
                            result
                                .as_ref()
                                .map_or(true, |(key, _)| key.target() == target)
                        })
                        .map(move |result| {
                            result.map(|(key, cached)| {
                                Self::reference_from_record(
                                    key.from(),
                                    key.target(),
                                    cached.as_ref(),
                                )
                            })
                        }),
                ))
            }
            ReferenceIndexBacking::Transient(index) => Ok(Box::new(TransientReferencesTo {
                index: index.read_arc(),
                target,
                cursor: after.map(|after| InverseReferenceKey::new(after.target(), after.from())),
            })),
        }
    }

    pub(crate) fn ensure_current<'a>(
        &self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
        revision: Revision,
    ) -> Result<(), EntityStorageError> {
        let Some(persistent) = self.persistent() else {
            return self.rebuild(functions, blocks);
        };
        let metadata = persistent
            .storage
            .get::<ProjectEntity, IndexMetadata>(&ProjectEntity::ReferenceIndex)?;
        if metadata.is_some_and(|metadata| metadata.revision() == revision) {
            return Ok(());
        }

        self.rebuild(functions, blocks)?;
        persistent.forward.flush()?;
        persistent.inverse.flush()?;
        self.mark_current(revision)
    }

    pub(crate) fn mark_current(&self, revision: Revision) -> Result<(), EntityStorageError> {
        let Some(persistent) = self.persistent() else {
            return Ok(());
        };
        persistent.storage.insert(
            &ProjectEntity::ReferenceIndex,
            &IndexMetadata::new(revision),
        )
    }

    fn rebuild<'a>(
        &self,
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

    fn clear_derived(&self) -> Result<FxHashSet<ReferenceKey>, EntityStorageError> {
        if let ReferenceIndexBacking::Transient(index) = &self.backing {
            let mut index = index.write();
            let mut asserted = FxHashSet::default();
            let asserted_references = index
                .forward
                .values()
                .filter(|reference| !reference.origin().is_derived())
                .copied()
                .collect::<Vec<_>>();
            index.forward.clear();
            index.inverse.clear();
            for reference in asserted_references {
                asserted.insert(ReferenceKey::new(reference.from(), reference.target()));
                index.insert(reference);
            }
            return Ok(asserted);
        }

        let persistent = self
            .persistent()
            .expect("persistent reference index required");
        let mut asserted = FxHashSet::default();
        let mut cursor = None;

        loop {
            let start = cursor_bound(cursor.as_ref());
            let batch = persistent
                .forward
                .try_iter_batch(start)?
                .into_iter()
                .map(|(key, cached)| (key, cached.origin()))
                .collect::<Vec<_>>();

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

    fn collect_range(
        &self,
        range: AddressRange,
        references: &mut Vec<Reference>,
    ) -> Result<(), EntityStorageError> {
        let end = range.end_address();
        let start = ReferenceKey::minimum_for(range.start_address());
        match &self.backing {
            ReferenceIndexBacking::Persistent { forward, .. } => {
                for result in forward.try_iter_range(Bound::Included(&start))? {
                    let (key, cached) = result?;
                    if key.from() > end {
                        break;
                    }
                    references.push(Self::reference_from_record(
                        key.from(),
                        key.target(),
                        cached.as_ref(),
                    ));
                }
            }
            ReferenceIndexBacking::Transient(index) => {
                references.extend(
                    index
                        .read()
                        .forward
                        .range((
                            Bound::Included(ReferenceKey::minimum_for(range.start_address())),
                            Bound::Unbounded,
                        ))
                        .take_while(|(key, _)| key.from() <= end)
                        .map(|(_, reference)| *reference),
                );
            }
        }
        Ok(())
    }

    fn reference_from_record(
        from: Address,
        target: ReferenceTarget,
        record: &ReferenceRecord,
    ) -> Reference {
        Reference::new(from, target, record.kind(), record.properties())
            .with_origin(record.origin())
    }
}

#[cfg(test)]
mod test {
    use std::io;

    use fugue_lifter::runtime::pcode::Inputs;

    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlGraph, IlIndexRange, IlMetadata, IlOpId, IlSourceSpan};
    use crate::il::pcode::{
        AddressAnnotation, AddressAnnotationValue, PCodeAddressContext, PCodeBuilder,
    };
    use crate::ir::{
        CodeBlockTable, FunctionId, FunctionTable, FunctionTableStaging, IncompleteCodeBlock,
        IncompleteFunction, Insn, InsnEntry,
    };
    use crate::lifter::{ContextSet, Language, Op, RawPCodeOp, Varnode, resolve_language};
    use crate::storage::entities::{EntityKeyPrefix, InMemoryEntityStorage};
    use crate::storage::segments::space::AddressSpaceId;

    fn address(space: u16, offset: u64) -> Address {
        Address::new(AddressSpaceId::from(space), offset)
    }

    fn index() -> Result<ReferenceIndex, EntityStorageError> {
        ReferenceIndex::new(EntityStorage::new(InMemoryEntityStorage::new()), None)
    }

    fn flow_reference(from: Address, to: Address) -> Reference {
        Reference::flow(from, to, ReferenceProperties::CALL).with_origin(ReferenceOrigin::Derived)
    }

    fn derived_read(from: Address, to: Address) -> Reference {
        Reference::data(from, to, ReferenceProperties::READ).with_origin(ReferenceOrigin::Derived)
    }

    fn insert_function(
        functions: &mut FunctionTable,
        blocks: &mut CodeBlockTable,
        language: &'static Language,
        entry: Address,
        targets: &[Address],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let instructions = targets
            .iter()
            .enumerate()
            .map(|(offset, target)| {
                let operations = [RawPCodeOp {
                    op: Op::Call,
                    inputs: Inputs::one(Varnode::new(language.default_space(), target.offset(), 8)),
                    output: Varnode::INVALID,
                }];

                Insn::from_resolved_flow(language, entry + offset, 1, &operations)
            })
            .collect::<Result<Vec<_>, _>>()?;

        insert_function_insns(functions, blocks, entry, instructions)?;

        Ok(())
    }

    fn insert_function_insns(
        functions: &mut FunctionTable,
        blocks: &mut CodeBlockTable,
        entry: Address,
        insns: Vec<Insn>,
    ) -> Result<FunctionId, Box<dyn std::error::Error>> {
        let mut function = IncompleteFunction::new(entry);
        let ids = insns
            .into_iter()
            .map(|insn| match function.insn_entry(insn.address()) {
                InsnEntry::Vacant(entry) => entry.insert(insn),
                InsnEntry::Occupied(entry) => entry.id(),
            })
            .collect::<Vec<_>>();
        let block =
            IncompleteCodeBlock::try_new(entry, ids.len().max(1), ids, ContextSet::default())
                .ok_or_else(|| io::Error::other("block construction failed"))?;
        function.push_block(block);

        let mut staging = FunctionTableStaging::default();
        let function = function.normalise()?;
        let record = functions.stage_materialisation(blocks, &mut staging, function)?;
        let id = record.id();
        let (batch, writes) = staging.prepare(functions, blocks)?;
        assert!(writes.is_empty());
        batch.publish(functions, blocks);
        Ok(id)
    }

    #[test]
    fn derived_kind_matches_ignores_kind_and_shadowing() {
        let from = address(0, 0x1000);
        let data_target = address(0, 0x2000);
        let flow_target = address(0, 0x3000);

        let current = [
            derived_read(from, data_target),
            flow_reference(from, flow_target),
        ];
        let derived = [derived_read(from, data_target)];
        assert!(ReferenceIndex::derived_kind_matches(
            &current,
            &derived,
            ReferenceKind::Data,
        ));

        let upgraded = [Reference::data(
            from,
            data_target,
            ReferenceProperties::READ | ReferenceProperties::WRITE,
        )
        .with_origin(ReferenceOrigin::Derived)];
        assert!(!ReferenceIndex::derived_kind_matches(
            &current,
            &upgraded,
            ReferenceKind::Data,
        ));

        let asserted = [derived_read(from, data_target).with_origin(ReferenceOrigin::Asserted)];
        assert!(ReferenceIndex::derived_kind_matches(
            &asserted,
            &derived,
            ReferenceKind::Data,
        ));
    }

    #[test]
    fn reference_properties_compose_and_predicate() {
        let reference = Reference::flow(
            address(0, 0x1000),
            address(0, 0x2000),
            ReferenceProperties::CALL
                | ReferenceProperties::CONDITIONAL
                | ReferenceProperties::COMPUTED,
        );
        assert!(reference.is_flow());
        assert!(reference.is_call());
        assert!(reference.is_conditional());
        assert!(reference.is_computed());
        assert!(!reference.is_jump());
        assert!(!reference.is_read());
    }

    #[test]
    fn reference_merges_data_access() {
        let merged = Reference::data(
            address(0, 0x1000),
            address(0, 0x2000),
            ReferenceProperties::READ,
        )
        .with_merged_properties(ReferenceProperties::WRITE);
        assert!(merged.is_read());
        assert!(merged.is_write());
        assert!(merged.is_data());
    }

    #[test]
    fn flow_kind_conversion_preserves_semantics() {
        let from = address(0, 0x1000);
        let to = address(0, 0x2000);
        assert!(Reference::from_flow(from, to, FlowKind::Call).is_call());
        assert!(Reference::from_flow(from, to, FlowKind::ICall).is_computed());
        assert!(Reference::from_flow(from, to, FlowKind::CBranch).is_conditional());
        assert!(Reference::from_flow(from, to, FlowKind::CBranch).is_jump());
        assert!(Reference::from_flow(from, to, FlowKind::Return).is_terminal());
        assert!(Reference::from_flow(from, to, FlowKind::Fall).has_fall_through());
    }

    #[test]
    fn reference_record_round_trips_kind_and_origin() {
        for (kind, properties) in [
            (
                ReferenceKind::Flow,
                ReferenceProperties::CALL | ReferenceProperties::CONDITIONAL,
            ),
            (
                ReferenceKind::Flow,
                ReferenceProperties::JUMP | ReferenceProperties::COMPUTED,
            ),
            (
                ReferenceKind::Data,
                ReferenceProperties::READ | ReferenceProperties::INDIRECT,
            ),
            (ReferenceKind::Data, ReferenceProperties::WRITE),
        ] {
            for origin in [ReferenceOrigin::Derived, ReferenceOrigin::Asserted] {
                let reference =
                    Reference::new(address(0, 0x1000), address(0, 0x2000), kind, properties)
                        .with_origin(origin);
                let record = ReferenceRecord::of(&reference);
                assert_eq!(record.kind(), kind);
                assert_eq!(record.properties(), properties);
                assert_eq!(record.origin(), origin);
            }
        }
    }

    #[test]
    fn reference_target_encoding_preserves_order() {
        let low = ReferenceTarget::from(address(0, 0x10));
        let mid = ReferenceTarget::from(address(0, 0x20));
        let high = ReferenceTarget::from(address(1, 0x00));
        let from = Address::MINIMUM;
        let low_encoded = ReferenceRecord::ID.key_for(&ReferenceKey::new(from, low));
        let mid_encoded = ReferenceRecord::ID.key_for(&ReferenceKey::new(from, mid));
        let high_encoded = ReferenceRecord::ID.key_for(&ReferenceKey::new(from, high));

        assert!(low_encoded < mid_encoded);
        assert!(mid_encoded < high_encoded);

        let (_, mut encoded) =
            EntityKeyPrefix::split(&low_encoded).expect("encoded key has prefix");
        assert_eq!(Address::decode(&mut encoded), Some(from));
        assert_eq!(ReferenceTarget::decode(&mut encoded), Some(low));
        assert!(encoded.is_empty());
    }

    #[test]
    fn reference_identity_ignores_properties() {
        let base = Reference::flow(
            address(0, 0x1000),
            address(0, 0x2000),
            ReferenceProperties::CALL,
        )
        .with_origin(ReferenceOrigin::Derived);
        let repainted = Reference::flow(
            address(0, 0x1000),
            address(0, 0x2000),
            ReferenceProperties::JUMP,
        );
        assert_eq!(base, repainted);
        assert_eq!(base.cmp(&repainted), Ordering::Equal);

        let elsewhere = Reference::flow(
            address(0, 0x1000),
            address(0, 0x3000),
            ReferenceProperties::CALL,
        )
        .with_origin(ReferenceOrigin::Derived);
        assert!(base < elsewhere);
    }

    #[test]
    fn reference_index_serves_both_directions() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let a = address(0, 0x1000);
        let b = address(0, 0x2000);
        let c = address(0, 0x3000);

        index.insert(&flow_reference(a, b))?;
        index.insert(&Reference::data(a, c, ReferenceProperties::READ))?;
        index.insert(&flow_reference(c, b))?;

        let from_a = index
            .references_from(a, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(from_a.len(), 2);
        assert_eq!(from_a[0].target().address(), Some(b));
        assert!(from_a[0].is_call());
        assert_eq!(from_a[1].target().address(), Some(c));
        assert!(from_a[1].is_read());

        let to_b = index
            .references_to(b.into(), None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(to_b.len(), 2);
        assert_eq!(to_b[0].from(), a);
        assert_eq!(to_b[1].from(), c);
        Ok(())
    }

    #[test]
    fn cross_space_references_scan_from_both_sides() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let base_from = address(0, 0x1000);
        let overlay_to = address(1, 0x2000);

        index.insert(&flow_reference(base_from, overlay_to))?;

        let from_side = index
            .references_from(base_from, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(from_side.len(), 1);
        assert_eq!(from_side[0].target().address(), Some(overlay_to));

        let to_side = index
            .references_to(overlay_to.into(), None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(to_side.len(), 1);
        assert_eq!(to_side[0].from(), base_from);
        Ok(())
    }

    #[test]
    fn reference_index_get_reads_record() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let a = address(0, 0x1000);
        let b = address(0, 0x2000);

        assert!(index.get(a, b.into())?.is_none());

        index.insert(&Reference::data(
            a,
            b,
            ReferenceProperties::READ | ReferenceProperties::INDIRECT,
        ))?;

        let stored = index
            .get(a, b.into())?
            .ok_or("reference absent after insert")?;
        assert!(stored.is_read());
        assert!(stored.is_indirect());
        assert!(stored.origin().is_asserted());
        Ok(())
    }

    #[test]
    fn reference_index_remove_clears_both_sides() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let a = address(0, 0x1000);
        let b = address(0, 0x2000);

        index.insert(&flow_reference(a, b))?;
        index.remove(a, b.into())?;

        assert!(
            index
                .references_from(a, None)?
                .collect::<Result<Vec<_>, _>>()?
                .is_empty()
        );
        assert!(
            index
                .references_to(b.into(), None)?
                .collect::<Result<Vec<_>, _>>()?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn reference_index_pages_from_cursor() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let from = address(0, 0x1000);
        for offset in 0..8u64 {
            index.insert(&flow_reference(from, address(0, 0x2000 + offset * 0x10)))?;
        }

        let mut walked = Vec::new();
        let mut cursor = None;
        loop {
            let page = index
                .references_from(from, cursor.as_ref())?
                .take(3)
                .collect::<Result<Vec<_>, _>>()?;
            if page.is_empty() {
                break;
            }
            cursor = page.last().copied();
            walked.extend(page);
        }

        let full = index
            .references_from(from, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(walked, full);
        assert_eq!(walked.len(), 8);
        assert!(walked.windows(2).all(|pair| pair[0] < pair[1]));
        Ok(())
    }

    #[test]
    fn reference_index_reads_persisted_rows() -> Result<(), Box<dyn std::error::Error>> {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let a = address(0, 0x1000);
        let b = address(0, 0x2000);

        let writer = ReferenceIndex::new(storage.clone(), None)?;
        writer.insert(&flow_reference(a, b))?;

        let reader = ReferenceIndex::new(storage.clone(), None)?;
        let from_a = reader
            .references_from(a, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(from_a.len(), 1);
        assert_eq!(from_a[0].target().address(), Some(b));
        Ok(())
    }

    #[test]
    fn reference_index_ensure_current_derives_flow_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let index = index()?;
        let mut functions = FunctionTable::new_transient();
        let mut blocks = CodeBlockTable::new_transient();
        let entry = address(0, 0x1000);
        let callee = address(0, 0x2000);

        insert_function(&mut functions, &mut blocks, language, entry, &[callee])?;

        index.ensure_current(functions.iter(), &blocks, Revision::new(1))?;

        let derived = index
            .references_from(entry, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(derived.len(), 1);
        assert_eq!(derived[0].target().address(), Some(callee));
        assert!(derived[0].is_call());
        assert!(derived[0].origin().is_derived());
        Ok(())
    }

    #[test]
    fn data_references_from_constant_pointer() -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let default_space = language.default_space();
        let insn_address = address(0, 0x1000);
        let data_space = insn_address.space();
        let data_address = 0x4000u64;
        let register_value = Varnode::new(language.register_space(), 0, 8);
        let load_operation = RawPCodeOp {
            op: Op::Load(default_space),
            inputs: Inputs::one(Varnode::constant(data_address, 8)),
            output: register_value,
        };
        let store_operation = RawPCodeOp {
            op: Op::Store(default_space),
            inputs: Inputs([Varnode::constant(data_address, 8), register_value]),
            output: Varnode::INVALID,
        };
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let annotations = [
            AddressAnnotation::new(
                IlOpId::try_from_index(0).unwrap(),
                AddressAnnotationValue::ComputedSpace(data_space),
            ),
            AddressAnnotation::new(
                IlOpId::try_from_index(1).unwrap(),
                AddressAnnotationValue::ComputedSpace(data_space),
            ),
        ];
        let mut context = PCodeAddressContext::new(insn_address, &annotations);
        let mut builder = PCodeBuilder::new(language, metadata, IlGraph::default());
        builder.push_lifted_operations(&[load_operation, store_operation], &mut context)?;
        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 2).unwrap(),
            insn_address,
            0,
            2,
        )]);
        let ir = builder.build(&CancellationToken::default())?;
        let artefact_refs = ir.data_references().collect::<Vec<_>>();

        assert_eq!(artefact_refs.len(), 2);
        assert_eq!(artefact_refs[0].from(), insn_address);
        assert_eq!(
            artefact_refs[0].target().address(),
            Some(Address::new(data_space, data_address))
        );
        assert!(artefact_refs[0].is_read());
        assert!(artefact_refs[0].origin().is_derived());
        assert_eq!(artefact_refs[1].from(), insn_address);
        assert!(artefact_refs[1].is_write());
        assert_eq!(
            artefact_refs[1].target().address(),
            Some(Address::new(data_space, data_address))
        );

        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let annotations = [AddressAnnotation::new(
            IlOpId::try_from_index(0).unwrap(),
            AddressAnnotationValue::ComputedSpace(data_space),
        )];
        let mut context = PCodeAddressContext::new(insn_address, &annotations);
        let mut builder = PCodeBuilder::new(language, metadata, IlGraph::default());
        let register_relative = RawPCodeOp {
            op: Op::Load(default_space),
            inputs: Inputs::one(Varnode::new(language.register_space(), 0x20, 8)),
            output: Varnode::new(language.register_space(), 0, 8),
        };
        builder.push_lifted_operations(&[register_relative], &mut context)?;
        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 1).unwrap(),
            insn_address,
            0,
            1,
        )]);
        let ir = builder.build(&CancellationToken::default())?;
        assert!(ir.data_references().next().is_none());

        Ok(())
    }

    #[test]
    fn block_reference_derivation_excludes_instruction_data_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let default_space = language.default_space();
        let insn_address = address(0, 0x1000);
        let data = 0x4000u64;

        let operations = [
            RawPCodeOp {
                op: Op::Load(default_space),
                inputs: Inputs::one(Varnode::constant(data, 8)),
                output: Varnode::new(language.register_space(), 0, 8),
            },
            RawPCodeOp {
                op: Op::Store(default_space),
                inputs: Inputs([
                    Varnode::constant(data, 8),
                    Varnode::new(language.register_space(), 0, 8),
                ]),
                output: Varnode::INVALID,
            },
        ];
        let read_modify_write = Insn::from_resolved_flow(language, insn_address, 1, &operations)?;

        let mut functions = FunctionTable::new_transient();
        let mut blocks = CodeBlockTable::new_transient();
        let function = insert_function_insns(
            &mut functions,
            &mut blocks,
            insn_address,
            vec![read_modify_write],
        )?;
        let function = functions
            .get_by_id(function)
            .expect("materialised function must exist");
        let derived = function.flow_references(&blocks);

        assert!(derived.iter().all(|reference| !reference.is_data()));

        Ok(())
    }

    #[test]
    fn rebuild_preserves_asserted_references() -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let index = index()?;
        let mut functions = FunctionTable::new_transient();
        let mut blocks = CodeBlockTable::new_transient();
        let entry = address(0, 0x1000);
        let callee = address(0, 0x2000);
        insert_function(&mut functions, &mut blocks, language, entry, &[callee])?;

        let asserted_from = address(0, 0x5000);
        let asserted_to = address(0, 0x6000);
        index.insert(
            &Reference::data(asserted_from, asserted_to, ReferenceProperties::READ)
                .with_origin(ReferenceOrigin::Asserted),
        )?;

        index.ensure_current(functions.iter(), &blocks, Revision::new(7))?;

        let survived = index.get(asserted_from, asserted_to.into())?;
        assert!(survived.is_some_and(|reference| reference.origin().is_asserted()));

        let derived = index
            .references_from(entry, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert!(derived.iter().any(|reference| {
            reference.target().address() == Some(callee) && reference.origin().is_derived()
        }));

        Ok(())
    }
}
