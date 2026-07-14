use std::cmp::Ordering;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::ops::Bound;
use std::sync::Arc;

use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;

use crate::ir::cfg::FlowKind;
use crate::ir::function::table::FunctionRef;
use crate::ir::{Address, AddressRange, AddressRangeSet, CodeBlockTable, RawAddress};
use crate::lifter::Language;
use crate::storage::EntityStorage;
use crate::storage::entities::schema::{
    ENTITY_KEY_REFERENCE_FORWARD_ID, ENTITY_KEY_REFERENCE_INVERSE_ID,
    ENTITY_REFERENCE_INDEX_HEADER_ID, ENTITY_REFERENCE_RECORD_ID,
};
use crate::storage::entities::{
    Entity, EntityCache, EntityId, EntityKey, EntityKeyId, EntityStorageError, ProjectEntity,
    WriteBackWorker,
};
use crate::storage::segments::space::AddressSpaceId;

const ADDRESS_KEY_SIZE: usize = size_of::<AddressSpaceId>() + size_of::<RawAddress>();

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
pub enum ReferenceClass {
    Flow = 0,
    Data = 1,
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
    pub struct ReferenceFlags: u16 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferenceKind {
    class: ReferenceClass,
    flags: ReferenceFlags,
}

impl ReferenceKind {
    pub fn flow(flags: ReferenceFlags) -> Self {
        Self {
            class: ReferenceClass::Flow,
            flags,
        }
    }

    pub fn data(flags: ReferenceFlags) -> Self {
        Self {
            class: ReferenceClass::Data,
            flags,
        }
    }

    pub fn call() -> Self {
        Self::flow(ReferenceFlags::CALL)
    }

    pub fn jump() -> Self {
        Self::flow(ReferenceFlags::JUMP)
    }

    pub fn read() -> Self {
        Self::data(ReferenceFlags::READ)
    }

    pub fn write() -> Self {
        Self::data(ReferenceFlags::WRITE)
    }

    pub fn conditional(mut self) -> Self {
        self.flags |= ReferenceFlags::CONDITIONAL;
        self
    }

    pub fn computed(mut self) -> Self {
        self.flags |= ReferenceFlags::COMPUTED;
        self
    }

    pub fn indirect(mut self) -> Self {
        self.flags |= ReferenceFlags::INDIRECT;
        self
    }

    pub fn from_flow(kind: FlowKind) -> Self {
        let flags = match kind {
            FlowKind::Branch => ReferenceFlags::JUMP,
            FlowKind::CBranch => ReferenceFlags::JUMP | ReferenceFlags::CONDITIONAL,
            FlowKind::IBranch => ReferenceFlags::JUMP | ReferenceFlags::COMPUTED,
            FlowKind::Fall => ReferenceFlags::FALLS_THROUGH,
            FlowKind::Call => ReferenceFlags::CALL,
            FlowKind::ICall => ReferenceFlags::CALL | ReferenceFlags::COMPUTED,
            FlowKind::ServiceCall => ReferenceFlags::CALL,
            FlowKind::Return => ReferenceFlags::TERMINAL,
            FlowKind::SwitchBranch => ReferenceFlags::JUMP | ReferenceFlags::COMPUTED,
            FlowKind::SwitchCall => ReferenceFlags::CALL | ReferenceFlags::COMPUTED,
            FlowKind::TailCallBranch => {
                ReferenceFlags::CALL | ReferenceFlags::JUMP | ReferenceFlags::TERMINAL
            }
        };
        Self::flow(flags)
    }

    pub fn class(&self) -> ReferenceClass {
        self.class
    }

    pub fn flags(&self) -> ReferenceFlags {
        self.flags
    }

    pub fn merged(self, other: ReferenceKind) -> Self {
        Self {
            class: self.class,
            flags: self.flags | other.flags,
        }
    }

    pub fn is_flow(&self) -> bool {
        self.class == ReferenceClass::Flow
    }

    pub fn is_data(&self) -> bool {
        self.class == ReferenceClass::Data
    }

    pub fn is_call(&self) -> bool {
        self.flags.contains(ReferenceFlags::CALL)
    }

    pub fn is_jump(&self) -> bool {
        self.flags.contains(ReferenceFlags::JUMP)
    }

    pub fn is_conditional(&self) -> bool {
        self.flags.contains(ReferenceFlags::CONDITIONAL)
    }

    pub fn is_computed(&self) -> bool {
        self.flags.contains(ReferenceFlags::COMPUTED)
    }

    pub fn is_terminal(&self) -> bool {
        self.flags.contains(ReferenceFlags::TERMINAL)
    }

    pub fn has_fall_through(&self) -> bool {
        self.flags.contains(ReferenceFlags::FALLS_THROUGH)
    }

    pub fn is_read(&self) -> bool {
        self.flags.contains(ReferenceFlags::READ)
    }

    pub fn is_write(&self) -> bool {
        self.flags.contains(ReferenceFlags::WRITE)
    }

    pub fn is_indirect(&self) -> bool {
        self.flags.contains(ReferenceFlags::INDIRECT)
    }

    pub(crate) fn from_parts(class: ReferenceClass, flags: ReferenceFlags) -> Self {
        Self { class, flags }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperandSlot {
    Mnemonic,
    Operand(u8),
}

impl OperandSlot {
    const MAX_OPERAND: u8 = u8::MAX - 1;

    pub fn operand(index: u8) -> Self {
        debug_assert!(index <= Self::MAX_OPERAND, "operand index out of range");
        Self::Operand(index)
    }

    fn code(self) -> u8 {
        match self {
            Self::Mnemonic => 0,
            Self::Operand(index) => index + 1,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Mnemonic,
            other => Self::Operand(other - 1),
        }
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.code());
    }

    pub(crate) fn decode(buf: &mut &[u8]) -> Option<Self> {
        if buf.remaining() < 1 {
            return None;
        }
        Some(Self::from_code(buf.get_u8()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReferenceTarget {
    Address(Address),
}

impl ReferenceTarget {
    const TAG_ADDRESS: u8 = 0;
    const ADDRESS_BODY_SIZE: usize = ADDRESS_KEY_SIZE;

    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(address) => Some(*address),
        }
    }

    fn minimum() -> Self {
        Self::Address(Address::zero(AddressSpaceId::from(0u16)))
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
    slot: OperandSlot,
    target: ReferenceTarget,
    kind: ReferenceKind,
    origin: ReferenceOrigin,
}

impl Reference {
    pub fn new(
        from: Address,
        slot: OperandSlot,
        target: impl Into<ReferenceTarget>,
        kind: ReferenceKind,
    ) -> Self {
        Self {
            from,
            slot,
            target: target.into(),
            kind,
            origin: ReferenceOrigin::Asserted,
        }
    }

    pub fn with_origin(mut self, origin: ReferenceOrigin) -> Self {
        self.origin = origin;
        self
    }

    pub fn from(&self) -> Address {
        self.from
    }

    pub fn slot(&self) -> OperandSlot {
        self.slot
    }

    pub fn target(&self) -> ReferenceTarget {
        self.target
    }

    pub fn kind(&self) -> ReferenceKind {
        self.kind
    }

    pub fn origin(&self) -> ReferenceOrigin {
        self.origin
    }
}

impl PartialEq for Reference {
    fn eq(&self, other: &Self) -> bool {
        self.from == other.from && self.slot == other.slot && self.target == other.target
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
            .then_with(|| self.slot.cmp(&other.slot))
            .then_with(|| self.target.cmp(&other.target))
    }
}

impl Hash for Reference {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.from.hash(state);
        self.slot.hash(state);
        self.target.hash(state);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferenceKey {
    from: Address,
    slot: OperandSlot,
    target: ReferenceTarget,
}

impl ReferenceKey {
    pub fn new(from: Address, slot: OperandSlot, target: ReferenceTarget) -> Self {
        Self { from, slot, target }
    }

    pub fn from(&self) -> Address {
        self.from
    }

    pub fn slot(&self) -> OperandSlot {
        self.slot
    }

    pub fn target(&self) -> ReferenceTarget {
        self.target
    }

    fn minimum_for(from: Address) -> Self {
        Self::new(from, OperandSlot::Mnemonic, ReferenceTarget::minimum())
    }
}

impl EntityKey for ReferenceKey {
    const ID: EntityKeyId = ENTITY_KEY_REFERENCE_FORWARD_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < ADDRESS_KEY_SIZE {
            return None;
        }
        let from = Address::decode(&buf[..ADDRESS_KEY_SIZE])?;
        let mut rest = &buf[ADDRESS_KEY_SIZE..];
        let slot = OperandSlot::decode(&mut rest)?;
        let target = ReferenceTarget::decode(&mut rest)?;
        if !rest.is_empty() {
            return None;
        }
        Some(Self { from, slot, target })
    }

    fn encode(&self, buf: &mut BytesMut) {
        self.from.encode(buf);
        self.slot.encode(buf);
        self.target.encode(buf);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InverseReferenceKey {
    target: ReferenceTarget,
    from: Address,
    slot: OperandSlot,
}

impl InverseReferenceKey {
    fn new(target: ReferenceTarget, from: Address, slot: OperandSlot) -> Self {
        Self { target, from, slot }
    }

    fn minimum_for(target: ReferenceTarget) -> Self {
        Self::new(
            target,
            Address::zero(AddressSpaceId::from(0u16)),
            OperandSlot::Mnemonic,
        )
    }
}

impl EntityKey for InverseReferenceKey {
    const ID: EntityKeyId = ENTITY_KEY_REFERENCE_INVERSE_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        let mut rest = buf;
        let target = ReferenceTarget::decode(&mut rest)?;
        if rest.len() < ADDRESS_KEY_SIZE {
            return None;
        }
        let from = Address::decode(&rest[..ADDRESS_KEY_SIZE])?;
        rest = &rest[ADDRESS_KEY_SIZE..];
        let slot = OperandSlot::decode(&mut rest)?;
        if !rest.is_empty() {
            return None;
        }
        Some(Self { target, from, slot })
    }

    fn encode(&self, buf: &mut BytesMut) {
        self.target.encode(buf);
        self.from.encode(buf);
        self.slot.encode(buf);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ReferenceRecord {
    class: ReferenceClass,
    flags: u16,
    origin: ReferenceOrigin,
}

impl ReferenceRecord {
    fn of(reference: &Reference) -> Self {
        Self {
            class: reference.kind().class(),
            flags: reference.kind().flags().bits(),
            origin: reference.origin(),
        }
    }

    fn kind(&self) -> ReferenceKind {
        ReferenceKind::from_parts(self.class, ReferenceFlags::from_bits_retain(self.flags))
    }

    fn origin(&self) -> ReferenceOrigin {
        self.origin
    }
}

impl Entity for ReferenceRecord {
    const ID: EntityId = ENTITY_REFERENCE_RECORD_ID;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct ReferenceIndexHeader {
    revision: u64,
}

impl ReferenceIndexHeader {
    fn new(revision: u64) -> Self {
        Self { revision }
    }

    fn revision(&self) -> u64 {
        self.revision
    }
}

impl Entity for ReferenceIndexHeader {
    const ID: EntityId = ENTITY_REFERENCE_INDEX_HEADER_ID;
}

#[derive(Debug, Error)]
pub enum ReferenceVerificationError {
    #[error("reference storage error: {0}")]
    Storage(#[from] EntityStorageError),
    #[error("reference mismatch: forward_only={forward_only:?}, inverse_only={inverse_only:?}")]
    Mismatch {
        forward_only: Vec<ReferenceKey>,
        inverse_only: Vec<ReferenceKey>,
    },
}

#[derive(Clone)]
pub struct ReferenceIndex {
    forward: EntityCache<ReferenceKey, ReferenceRecord>,
    inverse: EntityCache<InverseReferenceKey, ReferenceRecord>,
    storage: EntityStorage,
    language: &'static Language,
}

impl ReferenceIndex {
    const CACHE_BYTES: usize = 16 * 1024 * 1024;
    const CLEAR_BATCH_LEN: usize = 256;

    pub(crate) fn new(
        storage: EntityStorage,
        language: &'static Language,
    ) -> Result<Self, EntityStorageError> {
        let forward = EntityCache::new(storage.clone(), Self::CACHE_BYTES)?;
        let inverse = EntityCache::new(storage.clone(), Self::CACHE_BYTES)?;

        Ok(Self {
            forward,
            inverse,
            storage,
            language,
        })
    }

    pub(crate) fn new_with(
        storage: EntityStorage,
        worker: Arc<WriteBackWorker>,
        language: &'static Language,
    ) -> Self {
        let forward = EntityCache::with_worker(storage.clone(), worker.clone(), Self::CACHE_BYTES);
        let inverse = EntityCache::with_worker(storage.clone(), worker, Self::CACHE_BYTES);

        Self {
            forward,
            inverse,
            storage,
            language,
        }
    }

    pub(crate) fn insert(&self, reference: &Reference) -> Result<(), EntityStorageError> {
        let record = ReferenceRecord::of(reference);
        self.forward.try_put(
            ReferenceKey::new(reference.from(), reference.slot(), reference.target()),
            record,
        )?;
        self.inverse.try_put(
            InverseReferenceKey::new(reference.target(), reference.from(), reference.slot()),
            record,
        )?;

        Ok(())
    }

    pub(crate) fn remove(
        &self,
        from: Address,
        slot: OperandSlot,
        target: ReferenceTarget,
    ) -> Result<(), EntityStorageError> {
        self.forward
            .try_remove(&ReferenceKey::new(from, slot, target))?;
        self.inverse
            .try_remove(&InverseReferenceKey::new(target, from, slot))
    }

    pub(crate) fn get(
        &self,
        from: Address,
        slot: OperandSlot,
        target: ReferenceTarget,
    ) -> Result<Option<Reference>, EntityStorageError> {
        let key = ReferenceKey::new(from, slot, target);
        let Some(cached) = self.forward.try_get(&key)? else {
            return Ok(None);
        };
        Ok(Some(Self::reference_from_record(
            from,
            slot,
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
        let start_key;
        let start = match after {
            Some(after) => {
                start_key = ReferenceKey::new(after.from(), after.slot(), after.target());
                Bound::Excluded(&start_key)
            }
            None => {
                start_key = ReferenceKey::minimum_for(from);
                Bound::Included(&start_key)
            }
        };

        Ok(self
            .forward
            .try_scan_range(start)?
            .take_while(move |result| result.as_ref().map_or(true, |(key, _)| key.from() == from))
            .map(move |result| {
                result.map(|(key, cached)| {
                    Self::reference_from_record(
                        key.from(),
                        key.slot(),
                        key.target(),
                        cached.as_ref(),
                    )
                })
            }))
    }

    pub(crate) fn references_to(
        &self,
        target: ReferenceTarget,
        after: Option<&Reference>,
    ) -> Result<impl Iterator<Item = Result<Reference, EntityStorageError>> + '_, EntityStorageError>
    {
        let start_key;
        let start = match after {
            Some(after) => {
                start_key = InverseReferenceKey::new(after.target(), after.from(), after.slot());
                Bound::Excluded(&start_key)
            }
            None => {
                start_key = InverseReferenceKey::minimum_for(target);
                Bound::Included(&start_key)
            }
        };

        Ok(self
            .inverse
            .try_scan_range(start)?
            .take_while(move |result| {
                result
                    .as_ref()
                    .map_or(true, |(key, _)| key.target == target)
            })
            .map(move |result| {
                result.map(|(key, cached)| {
                    Self::reference_from_record(key.from, key.slot, key.target, cached.as_ref())
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
            .get::<ProjectEntity, ReferenceIndexHeader>(&ProjectEntity::ReferenceIndex)?;

        if header.is_some_and(|header| header.revision() == revision) {
            return Ok(());
        }

        self.rebuild(functions, blocks)?;
        self.forward.flush()?;
        self.inverse.flush()?;
        self.mark_current(revision)
    }

    pub(crate) fn mark_current(&self, revision: u64) -> Result<(), EntityStorageError> {
        self.storage.insert(
            &ProjectEntity::ReferenceIndex,
            &ReferenceIndexHeader::new(revision),
        )
    }

    pub fn verify(&self) -> Result<(), ReferenceVerificationError> {
        for result in self.forward.try_scan_range(Bound::Unbounded)? {
            let (key, _) = result?;
            let inverse_key = InverseReferenceKey::new(key.target(), key.from(), key.slot());
            if self.inverse.try_get(&inverse_key)?.is_none() {
                return Err(ReferenceVerificationError::Mismatch {
                    forward_only: vec![key],
                    inverse_only: Vec::new(),
                });
            }
        }

        for result in self.inverse.try_scan_range(Bound::Unbounded)? {
            let (key, _) = result?;
            let forward_key = ReferenceKey::new(key.from, key.slot, key.target);
            if self.forward.try_get(&forward_key)?.is_none() {
                return Err(ReferenceVerificationError::Mismatch {
                    forward_only: Vec::new(),
                    inverse_only: vec![forward_key],
                });
            }
        }

        Ok(())
    }

    fn rebuild<'a>(
        &self,
        functions: impl IntoIterator<Item = FunctionRef<'a>>,
        blocks: &CodeBlockTable,
    ) -> Result<(), EntityStorageError> {
        let asserted = self.clear_derived()?;

        for function in functions {
            for reference in blocks.references(function.blocks().map(|(_, id)| id), self.language) {
                let key = ReferenceKey::new(reference.from(), reference.slot(), reference.target());
                if !asserted.contains(&key) {
                    self.insert(&reference)?;
                }
            }
        }

        Ok(())
    }

    fn clear_derived(&self) -> Result<HashSet<ReferenceKey>, EntityStorageError> {
        let mut asserted = HashSet::new();
        let mut cursor = None;

        loop {
            let start = cursor.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
            let batch = self
                .forward
                .try_scan_range(start)?
                .take(Self::CLEAR_BATCH_LEN)
                .map(|result| result.map(|(key, cached)| (key, cached.origin())))
                .collect::<Result<Vec<_>, _>>()?;

            let Some((last, _)) = batch.last() else {
                break;
            };
            cursor = Some(*last);

            for (key, origin) in batch {
                if origin.is_derived() {
                    self.remove(key.from, key.slot, key.target)?;
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
            self.remove(reference.from(), reference.slot(), reference.target())?;
        }
        Ok(())
    }

    pub(crate) fn replace_derived(
        &self,
        current: &[Reference],
        derived: impl IntoIterator<Item = Reference>,
    ) -> Result<(), EntityStorageError> {
        let mut asserted = HashSet::new();
        for reference in current {
            if reference.origin().is_derived() {
                self.remove(reference.from(), reference.slot(), reference.target())?;
            } else {
                asserted.insert(ReferenceKey::new(
                    reference.from(),
                    reference.slot(),
                    reference.target(),
                ));
            }
        }
        for reference in derived {
            let key = ReferenceKey::new(reference.from(), reference.slot(), reference.target());
            if !asserted.contains(&key) {
                self.insert(&reference)?;
            }
        }
        Ok(())
    }

    fn collect_range(
        &self,
        range: AddressRange,
        references: &mut Vec<Reference>,
    ) -> Result<(), EntityStorageError> {
        let end = range.end_address();
        let start = ReferenceKey::minimum_for(range.start_address());
        for result in self.forward.try_scan_range(Bound::Included(&start))? {
            let (key, cached) = result?;
            if key.from() > end {
                break;
            }
            references.push(Self::reference_from_record(
                key.from(),
                key.slot(),
                key.target(),
                cached.as_ref(),
            ));
        }
        Ok(())
    }

    fn reference_from_record(
        from: Address,
        slot: OperandSlot,
        target: ReferenceTarget,
        record: &ReferenceRecord,
    ) -> Reference {
        Reference::new(from, slot, target, record.kind()).with_origin(record.origin())
    }
}

pub(crate) struct ReferenceRevert {
    coverage: AddressRangeSet,
    previous: Vec<Reference>,
}

impl ReferenceRevert {
    pub(crate) fn capture(
        index: &ReferenceIndex,
        coverage: &AddressRangeSet,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self {
            coverage: coverage.clone(),
            previous: index.references_in(coverage)?,
        })
    }

    pub(crate) fn point(index: &ReferenceIndex, from: Address) -> Result<Self, EntityStorageError> {
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(from));
        Self::capture(index, &coverage)
    }

    pub(crate) fn had_derived(&self) -> bool {
        self.previous
            .iter()
            .any(|reference| reference.origin().is_derived())
    }

    pub(crate) fn previous(&self) -> &[Reference] {
        &self.previous
    }

    pub(crate) fn restore(self, index: &ReferenceIndex) -> Result<(), EntityStorageError> {
        index.clear_in(&self.coverage)?;
        for reference in self.previous {
            index.insert(&reference)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use fugue_lifter::runtime::pcode::Inputs;
    use fugue_lifter::{Op, PCodeOp, Varnode};

    use super::*;
    use crate::ir::{CodeBlock, Function, FunctionTable, Insn};
    use crate::lifter::{Language, resolve_language};
    use crate::storage::entities::InMemoryEntityStorage;

    fn address(space: u16, offset: u64) -> Address {
        Address::new(AddressSpaceId::from(space), offset)
    }

    #[test]
    fn test_reference_flags_compose_and_predicate() {
        let kind = ReferenceKind::call().conditional().computed();
        assert!(kind.is_flow());
        assert!(kind.is_call());
        assert!(kind.is_conditional());
        assert!(kind.is_computed());
        assert!(!kind.is_jump());
        assert!(!kind.is_read());
    }

    #[test]
    fn test_reference_kind_merges_data_access() {
        let merged = ReferenceKind::read().merged(ReferenceKind::write());
        assert!(merged.is_read());
        assert!(merged.is_write());
        assert!(merged.is_data());
    }

    #[test]
    fn test_flow_kind_conversion_preserves_semantics() {
        assert!(ReferenceKind::from_flow(FlowKind::Call).is_call());
        assert!(ReferenceKind::from_flow(FlowKind::ICall).is_computed());
        assert!(ReferenceKind::from_flow(FlowKind::CBranch).is_conditional());
        assert!(ReferenceKind::from_flow(FlowKind::CBranch).is_jump());
        assert!(ReferenceKind::from_flow(FlowKind::Return).is_terminal());
        assert!(ReferenceKind::from_flow(FlowKind::Fall).has_fall_through());
    }

    #[test]
    fn test_reference_record_round_trips_kind_and_origin() {
        for kind in [
            ReferenceKind::call().conditional(),
            ReferenceKind::jump().computed(),
            ReferenceKind::read().indirect(),
            ReferenceKind::write(),
        ] {
            for origin in [ReferenceOrigin::Derived, ReferenceOrigin::Asserted] {
                let reference = Reference::new(
                    address(0, 0x1000),
                    OperandSlot::Mnemonic,
                    address(0, 0x2000),
                    kind,
                )
                .with_origin(origin);
                let record = ReferenceRecord::of(&reference);
                assert_eq!(record.kind(), kind);
                assert_eq!(record.origin(), origin);
            }
        }
    }

    #[test]
    fn test_operand_slot_encoding_orders_mnemonic_first() {
        let mut mnemonic = BytesMut::new();
        OperandSlot::Mnemonic.encode(&mut mnemonic);
        let mut operand = BytesMut::new();
        OperandSlot::operand(0).encode(&mut operand);
        assert!(mnemonic.as_ref() < operand.as_ref());

        for slot in [
            OperandSlot::Mnemonic,
            OperandSlot::operand(0),
            OperandSlot::operand(7),
        ] {
            let mut buf = BytesMut::new();
            slot.encode(&mut buf);
            let mut slice = buf.as_ref();
            assert_eq!(OperandSlot::decode(&mut slice), Some(slot));
        }
    }

    #[test]
    fn test_reference_target_encoding_preserves_order() {
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
    fn test_reference_identity_ignores_payload() {
        let base = Reference::new(
            address(0, 0x1000),
            OperandSlot::operand(1),
            address(0, 0x2000),
            ReferenceKind::call(),
        )
        .with_origin(ReferenceOrigin::Derived);
        let repainted = Reference::new(
            address(0, 0x1000),
            OperandSlot::operand(1),
            address(0, 0x2000),
            ReferenceKind::jump(),
        );
        assert_eq!(base, repainted);
        assert_eq!(base.cmp(&repainted), Ordering::Equal);

        let elsewhere = Reference::new(
            address(0, 0x1000),
            OperandSlot::operand(2),
            address(0, 0x2000),
            ReferenceKind::call(),
        )
        .with_origin(ReferenceOrigin::Derived);
        assert!(base < elsewhere);
    }

    fn index() -> Result<ReferenceIndex, EntityStorageError> {
        let language = resolve_language("x86:LE:64").expect("x86 language available");
        ReferenceIndex::new(EntityStorage::new(InMemoryEntityStorage::new()), language)
    }

    fn flow_reference(from: Address, to: Address) -> Reference {
        Reference::new(from, OperandSlot::Mnemonic, to, ReferenceKind::call())
            .with_origin(ReferenceOrigin::Derived)
    }

    #[test]
    fn test_reference_index_serves_both_directions() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let a = address(0, 0x1000);
        let b = address(0, 0x2000);
        let c = address(0, 0x3000);

        index.insert(
            &Reference::new(a, OperandSlot::Mnemonic, b, ReferenceKind::call())
                .with_origin(ReferenceOrigin::Derived),
        )?;
        index.insert(&Reference::new(
            a,
            OperandSlot::operand(0),
            c,
            ReferenceKind::read(),
        ))?;
        index.insert(&flow_reference(c, b))?;

        let from_a = index
            .references_from(a, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(from_a.len(), 2);
        assert_eq!(from_a[0].slot(), OperandSlot::Mnemonic);
        assert_eq!(from_a[0].target().address(), Some(b));
        assert!(from_a[0].kind().is_call());
        assert_eq!(from_a[1].slot(), OperandSlot::operand(0));
        assert!(from_a[1].kind().is_read());

        let to_b = index
            .references_to(b.into(), None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(to_b.len(), 2);
        assert_eq!(to_b[0].from(), a);
        assert_eq!(to_b[1].from(), c);

        index.verify()?;
        Ok(())
    }

    #[test]
    fn test_cross_space_references_scan_from_both_sides() -> Result<(), Box<dyn std::error::Error>>
    {
        let index = index()?;
        let base_from = Address::new(AddressSpaceId::from(0u16), 0x1000u64);
        let overlay_to = Address::new(AddressSpaceId::from(1u16), 0x2000u64);

        index.insert(
            &Reference::new(
                base_from,
                OperandSlot::Mnemonic,
                overlay_to,
                ReferenceKind::call(),
            )
            .with_origin(ReferenceOrigin::Derived),
        )?;

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

        index.verify()?;
        Ok(())
    }

    #[test]
    fn test_reference_index_get_reads_payload() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let a = address(0, 0x1000);
        let b = address(0, 0x2000);

        assert!(index.get(a, OperandSlot::Mnemonic, b.into())?.is_none());

        index.insert(&Reference::new(
            a,
            OperandSlot::Mnemonic,
            b,
            ReferenceKind::read().indirect(),
        ))?;

        let stored = index
            .get(a, OperandSlot::Mnemonic, b.into())?
            .ok_or("reference absent after insert")?;
        assert!(stored.kind().is_read());
        assert!(stored.kind().is_indirect());
        assert!(stored.origin().is_asserted());
        Ok(())
    }

    #[test]
    fn test_reference_index_remove_clears_both_sides() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let a = address(0, 0x1000);
        let b = address(0, 0x2000);

        index.insert(&flow_reference(a, b))?;
        index.remove(a, OperandSlot::Mnemonic, b.into())?;

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
        index.verify()?;
        Ok(())
    }

    #[test]
    fn test_reference_index_pages_from_cursor() -> Result<(), Box<dyn std::error::Error>> {
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
    fn test_reference_index_reads_persisted_rows() -> Result<(), Box<dyn std::error::Error>> {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let a = address(0, 0x1000);
        let b = address(0, 0x2000);

        let language = resolve_language("x86:LE:64")?;
        let writer = ReferenceIndex::new(storage.clone(), language)?;
        writer.insert(&flow_reference(a, b))?;

        let reader = ReferenceIndex::new(storage.clone(), language)?;
        let from_a = reader
            .references_from(a, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(from_a.len(), 1);
        assert_eq!(from_a[0].target().address(), Some(b));
        Ok(())
    }

    #[test]
    fn test_reference_index_ensure_current_derives_flow_references()
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
        assert!(derived[0].kind().is_call());
        assert!(derived[0].origin().is_derived());
        index.verify()?;
        Ok(())
    }

    fn single_point(address: Address) -> AddressRangeSet {
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(address));
        coverage
    }

    #[test]
    fn test_replace_derived_in_preserves_asserted() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let from = address(0, 0x1000);
        let old_target = address(0, 0x2000);
        let asserted_target = address(0, 0x3000);
        let new_target = address(0, 0x4000);

        index.insert(&Reference::new(
            from,
            OperandSlot::operand(0),
            asserted_target,
            ReferenceKind::read(),
        ))?;
        index.insert(&flow_reference(from, old_target))?;

        let current = index.references_in(&single_point(from))?;
        index.replace_derived(&current, [flow_reference(from, new_target)])?;

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
        index.verify()?;
        Ok(())
    }

    #[test]
    fn test_reference_revert_restores_prior_state() -> Result<(), Box<dyn std::error::Error>> {
        let index = index()?;
        let from = address(0, 0x1000);
        let original = address(0, 0x2000);
        index.insert(&flow_reference(from, original))?;

        let revert = ReferenceRevert::capture(&index, &single_point(from))?;
        assert!(revert.had_derived());

        index.clear_in(&single_point(from))?;
        index.insert(&Reference::new(
            from,
            OperandSlot::operand(0),
            address(0, 0x9000),
            ReferenceKind::write(),
        ))?;

        revert.restore(&index)?;

        let from_refs = index
            .references_from(from, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(from_refs.len(), 1);
        assert_eq!(from_refs[0].target().address(), Some(original));
        assert!(from_refs[0].kind().is_call());
        index.verify()?;
        Ok(())
    }

    #[test]
    fn test_data_references_from_constant_pointer() -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let default_space = language.default_space();
        let insn_address = address(0, 0x1000);
        let data_address = 0x4000u64;

        let load = Insn::from_lifted(
            language,
            insn_address,
            1,
            vec![PCodeOp {
                op: Op::Load(default_space),
                inputs: Inputs::one(Varnode::constant(data_address, 8)),
                output: Varnode::new(language.register_space(), 0, 8),
            }],
        );
        let derived = load.data_references(language).collect::<Vec<_>>();
        assert_eq!(derived.len(), 1);
        assert_eq!(
            derived[0].target().address(),
            Some(address(0, data_address))
        );
        assert!(derived[0].kind().is_read());
        assert!(derived[0].origin().is_derived());

        let register_relative = Insn::from_lifted(
            language,
            insn_address,
            1,
            vec![PCodeOp {
                op: Op::Load(default_space),
                inputs: Inputs::one(Varnode::new(language.register_space(), 0x20, 8)),
                output: Varnode::new(language.register_space(), 0, 8),
            }],
        );
        assert!(register_relative.data_references(language).next().is_none());

        Ok(())
    }

    #[test]
    fn test_derivation_merges_read_and_write_at_one_address()
    -> Result<(), Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let default_space = language.default_space();
        let insn_address = address(0, 0x1000);
        let data = 0x4000u64;

        let read_modify_write = Insn::from_lifted(
            language,
            insn_address,
            1,
            vec![
                PCodeOp {
                    op: Op::Load(default_space),
                    inputs: Inputs::one(Varnode::constant(data, 8)),
                    output: Varnode::new(language.register_space(), 0, 8),
                },
                PCodeOp {
                    op: Op::Store(default_space),
                    inputs: Inputs([
                        Varnode::constant(data, 8),
                        Varnode::new(language.register_space(), 0, 8),
                    ]),
                    output: Varnode::INVALID,
                },
            ],
        );

        let mut blocks = CodeBlockTable::new_transient();
        let block_id = blocks.insert(insn_address, |id, address| {
            Ok(CodeBlock::try_new(id, address, 1, vec![read_modify_write])
                .expect("block construction failed"))
        })?;

        let derived = blocks.references([block_id], language);
        let data_references = derived
            .iter()
            .filter(|reference| reference.kind().is_data())
            .collect::<Vec<_>>();
        assert_eq!(data_references.len(), 1);
        assert!(data_references[0].kind().is_read());
        assert!(data_references[0].kind().is_write());
        assert_eq!(
            data_references[0].target().address(),
            Some(address(0, data))
        );

        Ok(())
    }

    #[test]
    fn test_rebuild_preserves_asserted_references() -> Result<(), Box<dyn std::error::Error>> {
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
            &Reference::new(
                asserted_from,
                OperandSlot::operand(0),
                asserted_to,
                ReferenceKind::read(),
            )
            .with_origin(ReferenceOrigin::Asserted),
        )?;

        index.ensure_current(functions.iter(), &blocks, 7)?;

        let survived = index.get(asserted_from, OperandSlot::operand(0), asserted_to.into())?;
        assert!(survived.is_some_and(|reference| reference.origin().is_asserted()));

        let derived = index
            .references_from(entry, None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert!(derived.iter().any(|reference| {
            reference.target().address() == Some(callee) && reference.origin().is_derived()
        }));
        index.verify()?;

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
                Insn::from_lifted(
                    language,
                    entry + offset,
                    1,
                    vec![PCodeOp {
                        op: Op::Call,
                        inputs: Inputs::one(Varnode::new(
                            language.default_space(),
                            target.offset(),
                            8,
                        )),
                        output: Varnode::INVALID,
                    }],
                )
            })
            .collect::<Vec<_>>();

        let block_id = blocks.insert(entry, |id, address| {
            Ok(
                CodeBlock::try_new(id, address, instructions.len().max(1), instructions)
                    .expect("block construction failed"),
            )
        })?;

        functions.insert(entry, |id, address| {
            Ok(Function::new(id, address).with_blocks([(address, block_id)]))
        })?;

        Ok(())
    }
}
