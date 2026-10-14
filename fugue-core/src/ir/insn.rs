use std::fmt;
use std::mem::size_of;

use smallvec::SmallVec;
use thiserror::Error;

use crate::il::pcode::raw::analysis::{RawPCodeFlow, RawPCodeFlows};
use crate::ir::{
    Address, AddressRange, AddressWithContext, FlowKind, FlowTarget, Id, Location, Reference,
    ReferenceOrigin, ToRawAddress,
};
use crate::lifter::{Language, Lifter, LifterError, Op, RawPCodeOp};
use crate::storage::schema::bitflags::archived_bitflags;
use crate::types::EstimateSize;

pub type InsnId = Id<Insn>;

#[derive(Debug, Error)]
pub enum InsnError {
    #[error("instruction size {size} exceeds retained limit")]
    InsnTooLarge { size: usize },
    #[error(transparent)]
    Lifting(#[from] LifterError),
}

impl InsnError {
    pub const fn insn_too_large(size: usize) -> Self {
        Self::InsnTooLarge { size }
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
    targets: SmallVec<[(u16, InsnTarget); 1]>,
    size: u8,
    delay_slot_size: u8,
}

impl Insn {
    pub(crate) fn from_direct_branch(
        address: impl Into<AddressWithContext>,
        size: usize,
        target: impl Into<AddressWithContext>,
        conditional: bool,
    ) -> Result<Self, InsnError> {
        Self::from_direct_flow(
            address.into(),
            size,
            InsnTarget::InterBlk(target.into()),
            conditional,
        )
    }

    pub(crate) fn from_direct_call(
        address: impl Into<AddressWithContext>,
        size: usize,
        target: impl Into<AddressWithContext>,
    ) -> Result<Self, InsnError> {
        Self::from_direct_flow(
            address.into(),
            size,
            InsnTarget::InterSub(target.into()),
            true,
        )
    }

    pub(crate) fn from_indirect_branch(address: Address, size: usize) -> Result<Self, InsnError> {
        let mut targets = SmallVec::new();
        targets.push((0, InsnTarget::InterBlkIndirect(None)));
        Self::from_flow_targets(address, size, targets)
    }

    pub(crate) fn from_indirect_call(
        address: impl Into<AddressWithContext>,
        size: usize,
    ) -> Result<Self, InsnError> {
        Self::from_direct_flow(
            address.into(),
            size,
            InsnTarget::InterSubIndirect(None),
            true,
        )
    }

    pub(crate) fn from_return(address: Address, size: usize) -> Result<Self, InsnError> {
        let mut targets = SmallVec::new();
        targets.push((0, InsnTarget::InterRet(None, true)));
        Self::from_flow_targets(address, size, targets)
    }

    fn from_direct_flow(
        address: AddressWithContext,
        size: usize,
        target: InsnTarget,
        fall_through: bool,
    ) -> Result<Self, InsnError> {
        let (address, fall_through_context) = address.into_parts();
        let mut targets = SmallVec::new();
        targets.push((0, target));
        if fall_through {
            targets.push((
                0,
                InsnTarget::IntraBlk(
                    AddressWithContext::new(address + size, fall_through_context),
                    0,
                    true,
                ),
            ));
        }
        Self::from_flow_targets(address, size, targets)
    }

    fn from_flow_targets(
        address: Address,
        size: usize,
        targets: SmallVec<[(u16, InsnTarget); 1]>,
    ) -> Result<Self, InsnError> {
        let properties = InsnProperties::from_targets(&targets) | InsnProperties::FLOW_RESOLVED;

        Ok(Self {
            address,
            properties,
            targets,
            size: size
                .try_into()
                .map_err(|_| InsnError::insn_too_large(size))?,
            delay_slot_size: 0,
        })
    }

    pub(crate) fn from_resolved_flow(
        lifter: &Lifter,
        address: Address,
        size: usize,
        operations: &[RawPCodeOp],
    ) -> Result<Self, InsnError> {
        let language = lifter.language();
        let canonicalise = |address: Address| {
            let (canonical, context) = lifter
                .arch()
                .canonicalise_address_with(address.raw_address(), lifter.context())?;
            Some(AddressWithContext::new(
                Address::new(address.space(), canonical),
                context,
            ))
        };
        let operation_count = operations.len() as u16;
        let next_address = address + size;
        let is_local = |location: &Location| location.address() == address;
        let is_fall_through = |location: &Location| location.address() == next_address;

        let mut targets = SmallVec::<[(u16, InsnTarget); 1]>::new();
        for (index, flow) in RawPCodeFlows::new(language, address, size, operations).iter() {
            let target = (|| {
                Some(match flow {
                    RawPCodeFlow::Branch(Some(location)) => {
                        if is_local(&location) {
                            InsnTarget::IntraIns(location, false)
                        } else if is_fall_through(&location) {
                            InsnTarget::IntraBlk(
                                canonicalise(location.address())?,
                                location.position(),
                                false,
                            )
                        } else {
                            InsnTarget::InterBlk(canonicalise(location.address())?)
                        }
                    }
                    RawPCodeFlow::Branch(None) => InsnTarget::InterBlkIndirect(None),
                    RawPCodeFlow::Call(Some(location)) => {
                        if location.position() != 0 {
                            InsnTarget::IntraIns(location, false)
                        } else {
                            InsnTarget::InterSub(canonicalise(location.address())?)
                        }
                    }
                    RawPCodeFlow::Call(None) => InsnTarget::InterSubIndirect(None),
                    RawPCodeFlow::FallThrough(location) => {
                        if is_local(&location) {
                            InsnTarget::IntraIns(location, true)
                        } else {
                            InsnTarget::IntraBlk(
                                canonicalise(location.address())?,
                                location.position(),
                                true,
                            )
                        }
                    }
                    RawPCodeFlow::Intrinsic => InsnTarget::Intrinsic,
                    RawPCodeFlow::Return(return_address) => InsnTarget::InterRet(
                        match return_address {
                            Some(address) => Some(canonicalise(address)?),
                            None => None,
                        },
                        index + 1 == operation_count,
                    ),
                })
            })();
            if let Some(target) = target {
                targets.push((index, target));
            }
        }
        let mut properties = InsnProperties::from_targets(&targets);
        if operations.is_empty() {
            properties |= InsnProperties::NOP;
        }

        properties |= InsnProperties::FLOW_RESOLVED;

        Ok(Self {
            address,
            properties,
            targets,
            size: size
                .try_into()
                .map_err(|_| InsnError::insn_too_large(size))?,
            delay_slot_size: 0,
        })
    }

    pub(crate) fn from_disassembly(
        address: Address,
        size: usize,
        properties: InsnProperties,
    ) -> Result<Self, InsnError> {
        Ok(Self {
            address,
            properties,
            targets: SmallVec::new(),
            size: size
                .try_into()
                .map_err(|_| InsnError::insn_too_large(size))?,
            delay_slot_size: 0,
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn next_address(&self) -> Address {
        self.address() + self.size as usize
    }

    pub fn properties(&self) -> InsnProperties {
        self.properties
    }

    pub fn size(&self) -> usize {
        self.size as _
    }

    pub fn delay_slot(&self) -> Option<AddressRange> {
        if self.delay_slot_size == 0 {
            return None;
        }
        AddressRange::from_size(
            self.address() + (self.size - self.delay_slot_size) as usize,
            u64::from(self.delay_slot_size),
        )
    }

    pub fn iter_targets<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a InsnTarget, InsnTargetKind, &'a AddressWithContext)> + 'a {
        self.targets.iter().filter_map(|(_, target)| {
            target
                .resolved()
                .map(|(kind, address)| (target, kind, address))
        })
    }

    pub fn flow_targets(&self) -> impl Iterator<Item = FlowTarget> + '_ {
        self.iter_targets().filter_map(|(target, _, address)| {
            FlowKind::from_insn_target(self, target)
                .map(|kind| FlowTarget::new(self.address(), address.clone(), kind))
        })
    }

    pub fn flow_references(&self) -> impl Iterator<Item = Reference> + '_ {
        self.iter_targets().filter_map(|(target, _, address)| {
            let kind = FlowKind::from_insn_target(self, target)?;
            if !kind.is_global() {
                return None;
            }
            Some(
                Reference::from_flow(self.address(), address.address(), kind)
                    .with_origin(ReferenceOrigin::Derived),
            )
        })
    }

    pub fn set_indirect_target(&mut self, target: AddressWithContext) {
        for (_, existing) in &mut self.targets {
            match existing {
                InsnTarget::InterBlkIndirect(None) => {
                    *existing = InsnTarget::InterBlkIndirect(Some(target.clone()));
                }
                InsnTarget::InterSubIndirect(None) => {
                    *existing = InsnTarget::InterSubIndirect(Some(target.clone()));
                }
                _ => (),
            }
        }

        self.properties = InsnProperties::from_targets(self.targets.as_slice())
            | (self.properties & !InsnProperties::FLOW & !InsnProperties::FALL_THROUGH);
    }

    pub fn call_target(&self) -> Option<&AddressWithContext> {
        self.targets.iter().find_map(|(_, target)| {
            if target.is_call() {
                target.address_with_context()
            } else {
                None
            }
        })
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

    pub fn has_fall_through(&self) -> bool {
        self.properties().contains(InsnProperties::FALL_THROUGH)
    }

    pub fn has_resolved_flow(&self) -> bool {
        self.properties().intersects(InsnProperties::FLOW_RESOLVED)
    }

    pub fn needs_flow_resolution(&self) -> bool {
        self.properties()
            .intersects(InsnProperties::NEEDS_FLOW_RESOLUTION)
    }

    pub(crate) fn indirect_target_pointer(
        &self,
        language: &'static Language,
        operations: &[RawPCodeOp],
    ) -> Option<Address> {
        let (position, target) = operations
            .iter()
            .enumerate()
            .find_map(|(index, operation)| {
                if !matches!(operation.op(), Op::IBranch | Op::ICall) {
                    return None;
                }
                operation.inputs().first().map(|target| (index, *target))
            })?;

        if let Some(target) = target.to_address(language) {
            return Some(Address::new(self.address().space(), target));
        }

        let definition = operations[..position]
            .iter()
            .rev()
            .find(|operation| operation.output() == Some(&target))?;

        if !matches!(definition.op(), Op::Copy) {
            return None;
        }

        definition
            .inputs()
            .first()
            .and_then(|source| source.to_address(language))
            .map(|source| Address::new(self.address().space(), source))
    }

    pub(crate) fn resolve_flow(
        &mut self,
        lifter: &mut Lifter,
        bytes: &[u8],
        operations: &mut Vec<RawPCodeOp>,
    ) -> Result<(), InsnError> {
        operations.clear();
        let size = lifter.lift(self.address(), bytes, operations)?;
        let encoded_size = self.size;
        *self = Self::from_resolved_flow(lifter, self.address(), size, operations)?;
        if encoded_size != 0 {
            self.delay_slot_size = self.size.saturating_sub(encoded_size);
        }
        Ok(())
    }

    pub fn remove_fall_through(&mut self) {
        self.targets.retain(|(_, target)| !target.is_fall_through());
        self.properties = InsnProperties::from_targets(self.targets.as_slice())
            | (self.properties & !InsnProperties::FLOW & !InsnProperties::FALL_THROUGH);
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
}

impl EstimateSize for Insn {
    fn estimate_size(&self) -> usize {
        let mut size = size_of::<Self>();
        if self.targets.spilled() {
            size = size.saturating_add(
                self.targets
                    .capacity()
                    .saturating_mul(size_of::<(u16, InsnTarget)>()),
            );
        }
        size
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct InsnProperties: u16 {
        const FALL_THROUGH          = 0b0000_0000_0000_0001;
        const BRANCH        = 0b0000_0000_0000_0010;
        const CALL          = 0b0000_0000_0000_0100;
        const RETURN        = 0b0000_0000_0000_1000;

        const INDIRECT      = 0b0000_0000_0001_0000;

        const BRANCH_DEST   = 0b0000_0000_0010_0000;
        const CALL_DEST     = 0b0000_0000_0100_0000;

        // 1. instruction's address referenced as an immediate
        //    on the rhs of an assignment
        // 2. the instruction is a fall-through from padding
        // 3. the instruction is an implicit fall-through target of two
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
        Self::FALL_THROUGH
    }
}

archived_bitflags!(InsnProperties, ArchivedInsnProperties, u16);

impl InsnProperties {
    fn from_targets(targets: &[(u16, InsnTarget)]) -> Self {
        let mut prop = Self::empty();

        for (_, target) in targets {
            match target {
                InsnTarget::IntraBlk(_, _, true) => prop |= Self::FALL_THROUGH,
                InsnTarget::IntraBlk(_, _, false) | InsnTarget::InterBlk(_) => prop |= Self::BRANCH,
                InsnTarget::InterBlkIndirect(_) => prop |= Self::BRANCH | Self::INDIRECT,
                InsnTarget::InterSub(_) => prop |= Self::CALL,
                InsnTarget::InterSubIndirect(_) => prop |= Self::CALL | Self::INDIRECT,
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
    Global,
    Local,
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
    InterBlk(AddressWithContext),
    InterBlkIndirect(Option<AddressWithContext>),
    InterRet(Option<AddressWithContext>, bool),
    InterSub(AddressWithContext),
    InterSubIndirect(Option<AddressWithContext>),
    IntraBlk(AddressWithContext, u16, bool),
    IntraIns(Location, bool),
    Intrinsic,
}

impl InsnTarget {
    pub fn is_call(&self) -> bool {
        matches!(self, Self::InterSub(_) | Self::InterSubIndirect(_))
    }

    pub fn is_fall_through(&self) -> bool {
        matches!(self, Self::IntraIns(_, true) | Self::IntraBlk(_, _, true))
    }

    pub fn is_indirect(&self) -> bool {
        matches!(
            self,
            Self::InterBlkIndirect(_) | Self::InterSubIndirect(_) | Self::InterRet(None, _)
        )
    }

    pub fn is_intrinsic(&self) -> bool {
        matches!(self, Self::Intrinsic)
    }

    pub fn is_return(&self) -> bool {
        matches!(self, Self::InterRet(..))
    }

    pub fn address(&self) -> Option<Address> {
        match self {
            Self::IntraIns(location, _) => Some(location.address()),
            _ => self.address_with_context().map(AddressWithContext::address),
        }
    }

    fn address_with_context(&self) -> Option<&AddressWithContext> {
        match self {
            Self::IntraBlk(address, _, _)
            | Self::InterBlk(address)
            | Self::InterBlkIndirect(Some(address))
            | Self::InterSub(address)
            | Self::InterSubIndirect(Some(address))
            | Self::InterRet(Some(address), _) => Some(address),
            _ => None,
        }
    }

    pub(crate) fn resolved(&self) -> Option<(InsnTargetKind, &AddressWithContext)> {
        use InsnTarget::*;
        use InsnTargetKind::*;

        match self {
            IntraBlk(taken, 0, _) | InterBlk(taken) | InterBlkIndirect(Some(taken)) => {
                Some((Local, taken))
            }
            InterSub(taken) | InterSubIndirect(Some(taken)) | InterRet(Some(taken), _) => {
                Some((Global, taken))
            }
            _ => None,
        }
    }
}

impl fmt::Display for InsnTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntraIns(loc, _) => write!(f, "intra-instruction flow to {loc}"),
            Self::IntraBlk(address, position, _) => {
                write!(f, "intra-block flow to {address}.{position}")
            }
            Self::InterBlk(tgt) => write!(f, "inter-block flow to {tgt}"),
            Self::InterBlkIndirect(None) => write!(f, "unresolved indirect inter-block flow"),
            Self::InterBlkIndirect(Some(tgt)) => {
                write!(f, "indirect inter-block flow to {tgt}")
            }
            Self::InterSub(tgt) => write!(f, "inter-sub-routine flow to {tgt}"),
            Self::InterSubIndirect(None) => {
                write!(f, "unresolved indirect inter-sub-routine flow")
            }
            Self::InterSubIndirect(Some(tgt)) => {
                write!(f, "indirect inter-sub-routine flow to {tgt}")
            }
            Self::InterRet(None, _last) => {
                write!(f, "unresolved inter-sub-routine flow via return")
            }
            Self::InterRet(Some(tgt), _last) => {
                write!(f, "inter-sub-routine flow to {tgt} via return")
            }
            Self::Intrinsic => write!(f, "intrinsic flow"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::FlowKind;

    #[test]
    fn set_indirect_target_preserves_indirect_classification() -> Result<(), InsnError> {
        let address = Address::from(0x1000u64);
        let target = Address::from(0x2000u64);
        let mut insn = Insn::from_indirect_call(address, 4)?;

        insn.set_indirect_target(target.into());

        assert!(insn.is_indirect());
        assert_eq!(insn.call_target(), Some(&target.into()));
        assert_eq!(
            insn.flow_targets()
                .find(|flow| flow.kind().is_call())
                .expect("resolved indirect call must retain its call flow")
                .kind(),
            FlowKind::ICall
        );

        Ok(())
    }
}
