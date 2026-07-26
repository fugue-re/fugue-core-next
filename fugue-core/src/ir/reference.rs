use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::ops::Bound;
use std::sync::Arc;

use bytes::{Buf, BufMut, BytesMut};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::ir::cfg::FlowKind;
use crate::ir::{Address, AddressRange, AddressRangeSet, CodeBlockTable, FunctionRef, IndexHeader};
use crate::storage::EntityStorage;
use crate::storage::entities::schema::{
    ENTITY_KEY_REFERENCE_FORWARD_ID, ENTITY_KEY_REFERENCE_INVERSE_ID, ENTITY_REFERENCE_RECORD_ID,
};
use crate::storage::entities::{
    Entity, EntityCache, EntityId, EntityKey, EntityKeyId, EntityStorageError, ProjectEntity,
    WriteBackWorker,
};
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
        const FALLS_THROUGH = 0x0020;
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
            FlowKind::Fall => Self::FALLS_THROUGH,
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

impl ReferenceTarget {
    const TAG_ADDRESS: u8 = 0;
    const ADDRESS_BODY_SIZE: usize = Address::ENCODED_SIZE;

    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(address) => Some(*address),
        }
    }

    fn minimum() -> Self {
        Self::Address(Address::MINIMUM)
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Address(_) => Self::TAG_ADDRESS,
        }
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.tag());
        match self {
            Self::Address(address) => address.encode(buf),
        }
    }

    pub(crate) fn decode(buf: &mut &[u8]) -> Option<Self> {
        if buf.remaining() < 1 {
            return None;
        }
        match buf.get_u8() {
            Self::TAG_ADDRESS => {
                if buf.remaining() < Self::ADDRESS_BODY_SIZE {
                    return None;
                }
                let body = &buf[..Self::ADDRESS_BODY_SIZE];
                let address = Address::decode(body)?;
                buf.advance(Self::ADDRESS_BODY_SIZE);
                Some(Self::Address(address))
            }
            _ => None,
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
        self.properties.contains(ReferenceProperties::FALLS_THROUGH)
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

    fn minimum_for(from: Address) -> Self {
        Self::new(from, ReferenceTarget::minimum())
    }
}

impl EntityKey for ReferenceKey {
    const ID: EntityKeyId = ENTITY_KEY_REFERENCE_FORWARD_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < Address::ENCODED_SIZE {
            return None;
        }
        let from = Address::decode(&buf[..Address::ENCODED_SIZE])?;
        let mut rest = &buf[Address::ENCODED_SIZE..];
        let target = ReferenceTarget::decode(&mut rest)?;
        if !rest.is_empty() {
            return None;
        }
        Some(Self { from, target })
    }

    fn encode(&self, buf: &mut BytesMut) {
        self.from.encode(buf);
        self.target.encode(buf);
    }
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

impl EntityKey for InverseReferenceKey {
    const ID: EntityKeyId = ENTITY_KEY_REFERENCE_INVERSE_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        let mut rest = buf;
        let target = ReferenceTarget::decode(&mut rest)?;
        if rest.len() != Address::ENCODED_SIZE {
            return None;
        }
        let from = Address::decode(rest)?;
        Some(Self { target, from })
    }

    fn encode(&self, buf: &mut BytesMut) {
        self.target.encode(buf);
        self.from.encode(buf);
    }
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
    forward: EntityCache<ReferenceKey, ReferenceRecord>,
    inverse: EntityCache<InverseReferenceKey, ReferenceRecord>,
    storage: EntityStorage,
}

impl ReferenceIndex {
    const CACHE_BYTES: usize = 16 * 1024 * 1024;

    pub(crate) fn new(
        storage: EntityStorage,
        worker: Option<Arc<WriteBackWorker>>,
    ) -> Result<Self, EntityStorageError> {
        let forward =
            EntityCache::from_storage(storage.clone(), worker.clone(), Self::CACHE_BYTES)?;
        let inverse = EntityCache::from_storage(storage.clone(), worker, Self::CACHE_BYTES)?;

        Ok(Self {
            forward,
            inverse,
            storage,
        })
    }

    pub(crate) fn insert(&self, reference: &Reference) -> Result<(), EntityStorageError> {
        let record = ReferenceRecord::of(reference);
        self.forward.try_put(
            ReferenceKey::new(reference.from(), reference.target()),
            record,
        )?;
        self.inverse.try_put(
            InverseReferenceKey::new(reference.target(), reference.from()),
            record,
        )?;

        Ok(())
    }

    pub(crate) fn remove(
        &self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<(), EntityStorageError> {
        self.forward.try_remove(&ReferenceKey::new(from, target))?;
        self.inverse
            .try_remove(&InverseReferenceKey::new(target, from))
    }

    pub(crate) fn get(
        &self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<Option<Reference>, EntityStorageError> {
        let key = ReferenceKey::new(from, target);
        let Some(cached) = self.forward.try_get(&key)? else {
            return Ok(None);
        };
        Ok(Some(Self::reference_from_record(
            from,
            target,
            cached.as_ref(),
        )))
    }

    pub(crate) fn references_from(
        &self,
        from: Address,
        after: Option<&Reference>,
    ) -> Result<impl Iterator<Item = Result<Reference, EntityStorageError>> + '_, EntityStorageError>
    {
        let after = after.map(|after| ReferenceKey::new(after.from(), after.target()));
        let start = cursor_bound_or_minimum(after, ReferenceKey::minimum_for(from));

        Ok(self
            .forward
            .try_iter_range(start.as_ref())?
            .take_while(move |result| result.as_ref().map_or(true, |(key, _)| key.from() == from))
            .map(move |result| {
                result.map(|(key, cached)| {
                    Self::reference_from_record(key.from(), key.target(), cached.as_ref())
                })
            }))
    }

    pub(crate) fn references_to(
        &self,
        target: ReferenceTarget,
        after: Option<&Reference>,
    ) -> Result<impl Iterator<Item = Result<Reference, EntityStorageError>> + '_, EntityStorageError>
    {
        let after = after.map(|after| InverseReferenceKey::new(after.target(), after.from()));
        let start = cursor_bound_or_minimum(after, InverseReferenceKey::minimum_for(target));

        Ok(self
            .inverse
            .try_iter_range(start.as_ref())?
            .take_while(move |result| {
                result
                    .as_ref()
                    .map_or(true, |(key, _)| key.target() == target)
            })
            .map(move |result| {
                result.map(|(key, cached)| {
                    Self::reference_from_record(key.from(), key.target(), cached.as_ref())
                })
            }))
    }

    pub(crate) fn ensure_current<'a>(
        &self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
        revision: u64,
    ) -> Result<(), EntityStorageError> {
        let header = self
            .storage
            .get::<ProjectEntity, IndexHeader>(&ProjectEntity::ReferenceIndex)?;
        if header.is_some_and(|header| header.revision() == revision) {
            return Ok(());
        }

        self.rebuild(functions, blocks)?;
        self.forward.flush()?;
        self.inverse.flush()?;
        self.mark_current(revision)
    }

    pub(crate) fn mark_current(&self, revision: u64) -> Result<(), EntityStorageError> {
        self.storage
            .insert(&ProjectEntity::ReferenceIndex, &IndexHeader::new(revision))
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
        let mut asserted = FxHashSet::default();
        let mut cursor = None;

        loop {
            let start = cursor_bound(cursor.as_ref());
            let batch = self
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

    pub(crate) fn clear_in(&self, coverage: &AddressRangeSet) -> Result<(), EntityStorageError> {
        for reference in self.references_in(coverage)? {
            self.remove(reference.from(), reference.target())?;
        }
        Ok(())
    }

    pub(crate) fn replace_derived_of_kind(
        &self,
        current: &[Reference],
        derived: impl IntoIterator<Item = Reference>,
        kind: ReferenceKind,
    ) -> Result<(), EntityStorageError> {
        let mut occupied = FxHashSet::default();
        for reference in current {
            let key = ReferenceKey::new(reference.from(), reference.target());
            if reference.origin().is_derived() && reference.kind() == kind {
                self.remove(reference.from(), reference.target())?;
            } else {
                occupied.insert(key);
            }
        }
        for reference in derived {
            debug_assert_eq!(reference.kind(), kind);
            let key = ReferenceKey::new(reference.from(), reference.target());
            if !occupied.contains(&key) {
                self.insert(&reference)?;
            }
        }
        Ok(())
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
        for result in self.forward.try_iter_range(Bound::Included(&start))? {
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

pub(crate) enum ReferenceRevert {
    Coverage {
        coverage: AddressRangeSet,
        previous: Vec<Reference>,
    },
    Edge {
        from: Address,
        target: ReferenceTarget,
        previous: Option<Reference>,
    },
}

impl ReferenceRevert {
    pub(crate) fn capture(
        index: &ReferenceIndex,
        coverage: &AddressRangeSet,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::Coverage {
            coverage: coverage.clone(),
            previous: index.references_in(coverage)?,
        })
    }

    pub(crate) fn edge(
        from: Address,
        target: ReferenceTarget,
        previous: Option<Reference>,
    ) -> Self {
        Self::Edge {
            from,
            target,
            previous,
        }
    }

    pub(crate) fn had_derived(&self) -> bool {
        self.previous()
            .iter()
            .any(|reference| reference.origin().is_derived())
    }

    pub(crate) fn previous(&self) -> &[Reference] {
        match self {
            Self::Coverage { previous, .. } => previous,
            Self::Edge { previous, .. } => previous.as_slice(),
        }
    }

    pub(crate) fn restore(self, index: &ReferenceIndex) -> Result<(), EntityStorageError> {
        match self {
            Self::Coverage { coverage, previous } => {
                index.clear_in(&coverage)?;
                for reference in previous {
                    index.insert(&reference)?;
                }
                Ok(())
            }
            Self::Edge {
                from,
                target,
                previous,
            } => match previous {
                Some(reference) => index.insert(&reference),
                None => index.remove(from, target),
            },
        }
    }
}
#[cfg(test)]
mod test {
    use fugue_lifter::runtime::pcode::Inputs;

    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlGraph, IlIndexRange, IlMetadata, IlOpId, IlSourceSpan};
    use crate::il::pcode::{
        AddressAnnotation, AddressAnnotationValue, PCODE_SCHEMA_VERSION, PCodeAddressContext,
        PCodeBuilder,
    };
    use crate::ir::{CodeBlock, CodeBlockTableError, Function, FunctionId, FunctionTable, Insn};
    use crate::lifter::{Language, Op, RawPCodeOp, Varnode, resolve_language};
    use crate::storage::entities::InMemoryEntityStorage;
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

    fn single_point(address: Address) -> AddressRangeSet {
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(address));
        coverage
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

        let mut low_buf = BytesMut::new();
        low.encode(&mut low_buf);
        let mut mid_buf = BytesMut::new();
        mid.encode(&mut mid_buf);
        let mut high_buf = BytesMut::new();
        high.encode(&mut high_buf);

        assert!(low_buf.as_ref() < mid_buf.as_ref());
        assert!(mid_buf.as_ref() < high_buf.as_ref());

        let mut slice = low_buf.as_ref();
        assert_eq!(ReferenceTarget::decode(&mut slice), Some(low));
        assert!(slice.is_empty());
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

        index.ensure_current(functions.iter(), &blocks, 1)?;

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
    fn replace_derived_preserves_asserted() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let from = address(0, 0x1000);
        let old_target = address(0, 0x2000);
        let asserted_target = address(0, 0x3000);
        let new_target = address(0, 0x4000);

        index.insert(&Reference::data(
            from,
            asserted_target,
            ReferenceProperties::READ,
        ))?;
        index.insert(&flow_reference(from, old_target))?;

        let current = index.references_in(&single_point(from))?;
        index.replace_derived_of_kind(
            &current,
            [flow_reference(from, new_target)],
            ReferenceKind::Flow,
        )?;

        let from_refs = index
            .references_from(from, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(from_refs.len(), 2);
        assert!(from_refs.iter().any(|reference| {
            reference.target().address() == Some(asserted_target)
                && reference.origin().is_asserted()
        }));
        assert!(from_refs.iter().any(|reference| {
            reference.target().address() == Some(new_target) && reference.origin().is_derived()
        }));
        assert!(
            from_refs
                .iter()
                .all(|reference| reference.target().address() != Some(old_target))
        );
        Ok(())
    }

    #[test]
    fn reference_revert_restores_prior_state() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let from = address(0, 0x1000);
        let original = address(0, 0x2000);
        index.insert(&flow_reference(from, original))?;

        let revert = ReferenceRevert::capture(&index, &single_point(from))?;
        assert!(revert.had_derived());

        index.clear_in(&single_point(from))?;
        index.insert(&Reference::data(
            from,
            address(0, 0x9000),
            ReferenceProperties::WRITE,
        ))?;

        revert.restore(&index)?;

        let from_refs = index
            .references_from(from, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(from_refs.len(), 1);
        assert_eq!(from_refs[0].target().address(), Some(original));
        assert!(from_refs[0].is_call());
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
        let header = IlMetadata::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 0);
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
        let mut builder = PCodeBuilder::new(language, header, IlGraph::default());
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

        let header = IlMetadata::new(FunctionId::default(), PCODE_SCHEMA_VERSION, 0);
        let annotations = [AddressAnnotation::new(
            IlOpId::try_from_index(0).unwrap(),
            AddressAnnotationValue::ComputedSpace(data_space),
        )];
        let mut context = PCodeAddressContext::new(insn_address, &annotations);
        let mut builder = PCodeBuilder::new(language, header, IlGraph::default());
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

        let mut blocks = CodeBlockTable::new_transient();
        let block_id = blocks.insert(insn_address, |id, address| {
            CodeBlock::try_new(id, address, 1, vec![read_modify_write])
                .ok_or_else(|| CodeBlockTableError::other_with("block construction failed"))
        })?;

        let function = Function::new(FunctionId::default(), insn_address)
            .with_blocks([(insn_address, block_id)]);
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

        index.ensure_current(functions.iter(), &blocks, 7)?;

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

        let block_id = blocks.insert(entry, |id, address| {
            CodeBlock::try_new(id, address, instructions.len().max(1), instructions)
                .ok_or_else(|| CodeBlockTableError::other_with("block construction failed"))
        })?;

        functions.insert(entry, |id, address| {
            Ok(Function::new(id, address).with_blocks([(address, block_id)]))
        })?;

        Ok(())
    }
}
