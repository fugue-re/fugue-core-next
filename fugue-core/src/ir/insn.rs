use std::fmt;

use fugue_lifter::Op;
use fugue_lifter::runtime::language::Language;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::cfg::FlowKind;
use crate::ir::{Address, Id, Location, Reference, ReferenceOrigin, ToRawAddress};
use crate::lifter::PCodeOp;

pub type InsnId = Id<Insn>;

pub type InsnList = Vec<Insn>;

#[derive(Debug, Error)]
pub enum InsnError {
    #[error("instruction length {length} exceeds retained limit")]
    InstructionTooLong { length: usize },
}

impl InsnError {
    pub const fn instruction_too_long(length: usize) -> Self {
        Self::InstructionTooLong { length }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Insn {
    address: Address,
    properties: InsnProperties,
    targets: SmallVec<[(u16, InsnTarget); 2]>,
    length: u8,
}

impl Insn {
    pub(crate) fn from_resolved_flow(
        language: &'static Language,
        address: Address,
        length: usize,
        operations: &[PCodeOp],
    ) -> Result<Self, InsnError> {
        let mut targets = SmallVec::new();
        Self::push_targets_for_operations(language, address, length, operations, &mut targets);
        let mut properties = InsnProperties::from_targets(&targets);
        if operations.is_empty() {
            properties |= InsnProperties::NOP;
        }

        properties |= InsnProperties::FLOW_RESOLVED;

        Ok(Self {
            address,
            properties,
            targets,
            length: Self::checked_length(length)?,
        })
    }

    pub(crate) fn resolve_flow(
        &mut self,
        language: &'static Language,
        length: usize,
        operations: &[PCodeOp],
    ) -> Result<(), InsnError> {
        *self = Self::from_resolved_flow(language, self.address, length, operations)?;
        Ok(())
    }

    pub(crate) fn from_disassembly(
        address: Address,
        length: usize,
        properties: InsnProperties,
    ) -> Result<Self, InsnError> {
        Ok(Self {
            address,
            properties,
            targets: SmallVec::new(),
            length: Self::checked_length(length)?,
        })
    }

    fn checked_length(length: usize) -> Result<u8, InsnError> {
        length
            .try_into()
            .map_err(|_| InsnError::instruction_too_long(length))
    }

    pub(crate) fn push_targets_for_operations(
        language: &'static Language,
        address: Address,
        length: usize,
        operations: &[PCodeOp],
        targets: &mut SmallVec<[(u16, InsnTarget); 2]>,
    ) {
        let op_count = operations.len() as u16;
        let next_address = address + length;

        let is_local = |location: &Location| -> bool { location.address() == address };
        let is_fall = |location: &Location| -> bool { location.address() == next_address };

        let next_location = |index: u16| -> Location {
            if index >= op_count {
                Location::new(next_address, index - op_count)
            } else {
                Location::new(address, index)
            }
        };

        let push_call = |index: u16,
                         location: Option<Location>,
                         targets: &mut SmallVec<[(u16, InsnTarget); 2]>| {
            let Some(location) = location else {
                targets.push((index, InsnTarget::InterSub(None)));
                return;
            };

            if location.position() != 0 {
                targets.push((index, InsnTarget::IntraIns(location, false)));
            } else {
                targets.push((index, InsnTarget::InterSub(Some(location.address()))));
            }
        };

        let push_branch =
            |index: u16,
             location: Option<Location>,
             targets: &mut SmallVec<[(u16, InsnTarget); 2]>| {
                let Some(location) = location else {
                    targets.push((index, InsnTarget::Unresolved));
                    return;
                };

                if is_local(&location) {
                    targets.push((index, InsnTarget::IntraIns(location, false)));
                } else if is_fall(&location) {
                    targets.push((index, InsnTarget::IntraBlk(location, false)));
                } else {
                    targets.push((index, InsnTarget::InterBlk(location.address())));
                }
            };

        let push_fall =
            |index: u16, fall: Location, targets: &mut SmallVec<[(u16, InsnTarget); 2]>| {
                targets.push((
                    index,
                    if is_local(&fall) {
                        InsnTarget::IntraIns(fall, true)
                    } else {
                        InsnTarget::IntraBlk(fall, true)
                    },
                ));
            };

        if op_count == 0 {
            push_fall(0, next_location(1), targets);
            return;
        }

        for (index, operation) in operations.iter().enumerate() {
            let index = index as u16;
            let next = next_location(index + 1);
            let inputs = operation.inputs();

            match operation.op() {
                Op::Branch => {
                    let location = Location::absolute_from(language, address, inputs[0], index);
                    push_branch(index, location, targets);
                }
                Op::CBranch => {
                    let location = Location::absolute_from(language, address, inputs[0], index);
                    push_branch(index, location, targets);
                    push_fall(index, next, targets);
                }
                Op::IBranch => {
                    push_branch(index, None, targets);
                }
                Op::Call => {
                    let location = Location::absolute_from(language, address, inputs[0], index);
                    push_call(index, location, targets);
                    push_fall(index, next, targets);
                }
                Op::ICall => {
                    push_call(index, None, targets);
                    push_fall(index, next, targets);
                }
                Op::Return => {
                    let return_address = inputs[0]
                        .to_address(language)
                        .map(|address_offset| Address::new(address.space(), address_offset));
                    targets.push((
                        index,
                        InsnTarget::InterRet(return_address, index + 1 == op_count),
                    ));
                }
                Op::UserOp(_, _) => {
                    targets.push((index, InsnTarget::Intrinsic));
                    push_fall(index, next, targets);
                }
                _ => {
                    if index + 1 == op_count {
                        push_fall(index, next, targets);
                    }
                }
            }
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn next_address(&self) -> Address {
        self.address + self.length as usize
    }

    pub fn properties(&self) -> InsnProperties {
        self.properties
    }

    pub fn mark_branch_dest(&mut self) {
        self.properties |= InsnProperties::BRANCH_DEST;
    }

    pub fn unmark_branch_dest(&mut self) {
        self.properties.remove(InsnProperties::BRANCH_DEST);
    }

    pub fn mark_call_dest(&mut self) {
        self.properties |= InsnProperties::CALL_DEST;
    }

    pub fn unmark_call_dest(&mut self) {
        self.properties.remove(InsnProperties::CALL_DEST);
    }

    pub fn mark_maybe_taken(&mut self) {
        self.properties |= InsnProperties::MAYBE_TAKEN;
    }

    pub fn unmark_maybe_taken(&mut self) {
        self.properties.remove(InsnProperties::MAYBE_TAKEN);
    }

    pub fn mark_nonsense(&mut self) {
        self.properties |= InsnProperties::NONSENSE;
    }

    pub fn unmark_nonsense(&mut self) {
        self.properties.remove(InsnProperties::NONSENSE);
    }

    pub fn mark_halt(&mut self) {
        self.properties |= InsnProperties::HALT;
    }

    pub fn unmark_halt(&mut self) {
        self.properties.remove(InsnProperties::HALT);
    }

    pub fn mark_trap(&mut self) {
        self.properties |= InsnProperties::TRAP;
    }

    pub fn unmark_trap(&mut self) {
        self.properties.remove(InsnProperties::TRAP);
    }

    pub fn mark_invalid(&mut self) {
        self.properties |= InsnProperties::INVALID;
    }

    pub fn unmark_invalid(&mut self) {
        self.properties.remove(InsnProperties::INVALID);
    }

    pub fn mark_flow_resolved(&mut self) {
        self.properties |= InsnProperties::FLOW_RESOLVED;
    }

    pub fn mark_needs_flow_resolution(&mut self) {
        self.properties |= InsnProperties::NEEDS_FLOW_RESOLUTION;
    }

    pub fn is_taken(&self) -> bool {
        self.properties().intersects(InsnProperties::TAKEN)
    }

    pub fn is_nonsense(&self) -> bool {
        self.properties().intersects(InsnProperties::NONSENSE)
    }

    pub fn is_nop(&self) -> bool {
        self.properties().intersects(InsnProperties::NOP)
    }

    pub fn is_trap(&self) -> bool {
        self.properties().intersects(InsnProperties::TRAP)
    }

    pub fn is_invalid(&self) -> bool {
        self.properties().intersects(InsnProperties::INVALID)
    }

    pub fn is_halt(&self) -> bool {
        self.properties().intersects(InsnProperties::HALT)
    }

    pub fn is_branch(&self) -> bool {
        self.properties().intersects(InsnProperties::BRANCH)
    }

    pub fn is_call(&self) -> bool {
        self.properties().intersects(InsnProperties::CALL)
    }

    pub fn is_return(&self) -> bool {
        self.properties().intersects(InsnProperties::RETURN)
    }

    pub fn is_indirect(&self) -> bool {
        self.properties().intersects(InsnProperties::INDIRECT)
    }

    pub fn is_branch_dest(&self) -> bool {
        self.properties().intersects(InsnProperties::BRANCH_DEST)
    }

    pub fn is_call_dest(&self) -> bool {
        self.properties().intersects(InsnProperties::CALL_DEST)
    }

    pub fn is_flow(&self) -> bool {
        self.properties().intersects(InsnProperties::FLOW)
    }

    pub fn has_fall(&self) -> bool {
        self.properties().contains(InsnProperties::FALL)
    }

    pub fn has_resolved_flow(&self) -> bool {
        self.properties().intersects(InsnProperties::FLOW_RESOLVED)
    }

    pub fn needs_flow_resolution(&self) -> bool {
        self.properties()
            .intersects(InsnProperties::NEEDS_FLOW_RESOLUTION)
    }

    pub fn len(&self) -> usize {
        self.length as _
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn iter_targets<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a InsnTarget, InsnTargetKind, Address)> + 'a {
        use InsnTarget::*;
        use InsnTargetKind::*;

        self.targets.iter().filter_map(|(_, target)| match *target {
            IntraBlk(taken, _) if taken.position() == 0 => Some((target, Local, taken.address())),
            InterBlk(taken) => Some((target, Local, taken)),
            InterSub(Some(taken)) | InterRet(Some(taken), _) => Some((target, Global, taken)),
            _ => None,
        })
    }

    pub fn flow_references(&self) -> impl Iterator<Item = Reference> + '_ {
        self.iter_targets().filter_map(move |(target, kind, to)| {
            if kind != InsnTargetKind::Global {
                return None;
            }
            let flow = FlowKind::from_insn_target(self, target)?;
            Some(
                Reference::from_flow(self.address(), to, flow)
                    .with_origin(ReferenceOrigin::Derived),
            )
        })
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct InsnProperties: u16 {
        const FALL          = 0b0000_0000_0000_0001;
        const BRANCH        = 0b0000_0000_0000_0010;
        const CALL          = 0b0000_0000_0000_0100;
        const RETURN        = 0b0000_0000_0000_1000;

        const INDIRECT      = 0b0000_0000_0001_0000;

        const BRANCH_DEST   = 0b0000_0000_0010_0000;
        const CALL_DEST     = 0b0000_0000_0100_0000;

        // 1. instruction's address referenced as an immediate
        //    on the rhs of an assignment
        // 2. the instruction is a fall from padding
        // 3. the instruction is an implicit fall target of two
        //    or more overlapping blocks
        const MAYBE_TAKEN   = 0b0000_0000_1000_0000;

        // instruction is a semantic NO-OP
        const NOP           = 0b0000_0001_0000_0000;

        // instruction is a trap (e.g., UD2)
        const TRAP          = 0b0000_0010_0000_0000;

        // instruction falls into invalid
        const INVALID       = 0b0000_0100_0000_0000;

        // treat as invalid if repeated
        const NONSENSE      = 0b0000_1000_0000_0000;

        // instruction is a halt (e.g., HLT)
        const HALT          = 0b0001_0000_0000_0000;

        const FLOW_RESOLVED = 0b0010_0000_0000_0000;

        const NEEDS_FLOW_RESOLUTION = 0b0100_0000_0000_0000;

        const UNVIABLE      = Self::TRAP.bits() | Self::INVALID.bits();

        const DEST          = Self::BRANCH_DEST.bits() | Self::CALL_DEST.bits();
        const FLOW          = Self::BRANCH.bits() | Self::CALL.bits() | Self::RETURN.bits();

        const TAKEN         = Self::DEST.bits() | Self::MAYBE_TAKEN.bits();
    }
}

impl Default for InsnProperties {
    fn default() -> Self {
        Self::FALL
    }
}

#[repr(transparent)]
pub struct ArchivedInsnProperties(rkyv::primitive::ArchivedU16);
unsafe impl rkyv::Portable for ArchivedInsnProperties {}
unsafe impl rkyv::traits::NoUndef for ArchivedInsnProperties {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C>
    for ArchivedInsnProperties
where
    rkyv::primitive::ArchivedU16: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { rkyv::primitive::ArchivedU16::check_bytes(value.cast(), context) }
    }
}

impl rkyv::Archive for InsnProperties {
    type Archived = ArchivedInsnProperties;
    type Resolver = ();

    fn resolve(&self, _: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        out.write(ArchivedInsnProperties(
            rkyv::primitive::ArchivedU16::from_native(self.bits()),
        ));
    }
}

impl<S: rkyv::rancor::Fallible + ?Sized> rkyv::Serialize<S> for InsnProperties {
    fn serialize(&self, _serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized> rkyv::Deserialize<InsnProperties, D>
    for ArchivedInsnProperties
{
    fn deserialize(&self, _deserializer: &mut D) -> Result<InsnProperties, D::Error> {
        Ok(InsnProperties::from_bits_truncate(self.0.to_native()))
    }
}

impl InsnProperties {
    pub(crate) fn from_targets(targets: &[(u16, InsnTarget)]) -> Self {
        let mut prop = Self::empty();

        for (_, target) in targets.iter() {
            match target {
                InsnTarget::IntraBlk(_, true) => prop |= Self::FALL,
                InsnTarget::IntraBlk(_, false) | InsnTarget::InterBlk(_) => prop |= Self::BRANCH,
                InsnTarget::Unresolved => prop |= Self::BRANCH | Self::INDIRECT,
                InsnTarget::InterSub(Some(_)) => prop |= Self::CALL,
                InsnTarget::InterSub(None) => prop |= Self::CALL | Self::INDIRECT,
                InsnTarget::InterRet(Some(_), _) => prop |= Self::RETURN,
                InsnTarget::InterRet(None, _) => prop |= Self::RETURN | Self::INDIRECT,
                _ => (),
            }
        }

        prop
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum InsnTargetKind {
    Local,
    Global,
}

impl InsnTargetKind {
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }

    pub fn is_global(&self) -> bool {
        matches!(self, Self::Global)
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum InsnTarget {
    IntraIns(Location, bool),
    IntraBlk(Location, bool),
    InterBlk(Address),
    InterSub(Option<Address>),
    InterRet(Option<Address>, bool),
    Intrinsic,
    Unresolved,
}

impl InsnTarget {
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::IntraIns(location, _) | Self::IntraBlk(location, _) => Some(location.address()),
            Self::InterBlk(address)
            | Self::InterSub(Some(address))
            | Self::InterRet(Some(address), _) => Some(*address),
            Self::InterSub(None) | Self::InterRet(None, _) | Self::Intrinsic | Self::Unresolved => {
                None
            }
        }
    }
}

impl fmt::Display for InsnTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntraIns(loc, _) => write!(f, "intra-instruction flow to {loc}"),
            Self::IntraBlk(loc, _) => write!(f, "intra-block flow to {loc}"),
            Self::InterBlk(tgt) => write!(f, "inter-block flow to {tgt}"),
            Self::InterSub(None) => write!(f, "unresolved inter-sub-routine flow"),
            Self::InterSub(Some(tgt)) => write!(f, "inter-sub-routine flow to {tgt}"),
            Self::InterRet(None, _last) => {
                write!(f, "unresolved inter-sub-routine flow via return")
            }
            Self::InterRet(Some(tgt), _last) => {
                write!(f, "inter-sub-routine flow to {tgt} via return")
            }
            Self::Intrinsic => write!(f, "intrinsic flow"),
            Self::Unresolved => write!(f, "unresolved"),
        }
    }
}
