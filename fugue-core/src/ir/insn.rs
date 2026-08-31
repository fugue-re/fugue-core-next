use std::fmt;
use std::mem::size_of;

use smallvec::SmallVec;
use thiserror::Error;

use crate::il::pcode::{RawPCodeFlow, RawPCodeFlows};
use crate::ir::{Address, FlowTarget, Id, Location, Reference, ReferenceOrigin};
use crate::lifter::{Language, RawPCodeOp};
use crate::storage::schema::bitflags::archived_bitflags;
use crate::types::EstimateSize;

pub type InsnId = Id<Insn>;

#[derive(Debug, Error)]
pub enum InsnError {
    #[error("instruction size {size} exceeds retained limit")]
    InsnTooLarge { size: usize },
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
}

impl Insn {
    pub(crate) fn from_direct_branch(
        address: Address,
        size: usize,
        target: Address,
        conditional: bool,
    ) -> Result<Self, InsnError> {
        Self::from_direct_flow(address, size, InsnTarget::InterBlk(target), conditional)
    }

    pub(crate) fn from_direct_call(
        address: Address,
        size: usize,
        target: Address,
    ) -> Result<Self, InsnError> {
        Self::from_direct_flow(address, size, InsnTarget::InterSub(target), true)
    }

    pub(crate) fn from_indirect_branch(address: Address, size: usize) -> Result<Self, InsnError> {
        let mut targets = SmallVec::new();
        targets.push((0, InsnTarget::Unresolved));
        Self::from_flow_targets(address, size, targets)
    }

    pub(crate) fn from_indirect_call(address: Address, size: usize) -> Result<Self, InsnError> {
        Self::from_direct_flow(address, size, InsnTarget::InterSubIndirect(None), true)
    }

    pub(crate) fn from_return(address: Address, size: usize) -> Result<Self, InsnError> {
        let mut targets = SmallVec::new();
        targets.push((0, InsnTarget::InterRet(None, true)));
        Self::from_flow_targets(address, size, targets)
    }

    fn from_direct_flow(
        address: Address,
        size: usize,
        target: InsnTarget,
        fall_through: bool,
    ) -> Result<Self, InsnError> {
        let mut targets = SmallVec::new();
        targets.push((0, target));
        if fall_through {
            targets.push((
                0,
                InsnTarget::IntraBlk(Location::new(address + size, 0), true),
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
        })
    }

    pub(crate) fn from_resolved_flow(
        language: &'static Language,
        address: Address,
        size: usize,
        operations: &[RawPCodeOp],
    ) -> Result<Self, InsnError> {
        let operation_count = operations.len() as u16;
        let next_address = address + size;
        let is_local = |location: &Location| location.address() == address;
        let is_fall_through = |location: &Location| location.address() == next_address;

        let mut targets = SmallVec::new();
        for (index, flow) in RawPCodeFlows::new(language, address, size, operations).iter() {
            let target = match flow {
                RawPCodeFlow::Branch(Some(location)) => {
                    if is_local(location) {
                        InsnTarget::IntraIns(*location, false)
                    } else if is_fall_through(location) {
                        InsnTarget::IntraBlk(*location, false)
                    } else {
                        InsnTarget::InterBlk(location.address())
                    }
                }
                RawPCodeFlow::Branch(None) => InsnTarget::Unresolved,
                RawPCodeFlow::Call(Some(location)) => {
                    if location.position() != 0 {
                        InsnTarget::IntraIns(*location, false)
                    } else {
                        InsnTarget::InterSub(location.address())
                    }
                }
                RawPCodeFlow::Call(None) => InsnTarget::InterSubIndirect(None),
                RawPCodeFlow::FallThrough(location) => {
                    if is_local(location) {
                        InsnTarget::IntraIns(*location, true)
                    } else {
                        InsnTarget::IntraBlk(*location, true)
                    }
                }
                RawPCodeFlow::Intrinsic => InsnTarget::Intrinsic,
                RawPCodeFlow::Return(return_address) => {
                    InsnTarget::InterRet(*return_address, index + 1 == operation_count)
                }
            };
            targets.push((index, target));
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
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn properties(&self) -> InsnProperties {
        self.properties
    }

    pub fn size(&self) -> usize {
        self.size as _
    }

    pub fn iter_targets<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a InsnTarget, InsnTargetKind, Address)> + 'a {
        self.targets
            .iter()
            .filter_map(|(_, target)| target.resolved().map(|(kind, to)| (target, kind, to)))
    }

    pub fn flow_targets(&self) -> impl Iterator<Item = FlowTarget> + '_ {
        self.iter_targets()
            .filter_map(move |(target, _, to)| FlowTarget::from_insn_target(self, target, to))
    }

    pub fn flow_references(&self) -> impl Iterator<Item = Reference> + '_ {
        self.flow_targets().filter_map(|target| {
            if !target.kind().is_global() {
                return None;
            }
            Some(
                Reference::from_flow(target.from(), target.to(), target.kind())
                    .with_origin(ReferenceOrigin::Derived),
            )
        })
    }

    pub fn set_call_target(&mut self, target: Address) {
        for (_, existing) in self.targets.iter_mut() {
            if matches!(existing, InsnTarget::InterSubIndirect(None)) {
                *existing = InsnTarget::InterSubIndirect(Some(target));
            }
        }

        self.properties = InsnProperties::from_targets(&self.targets)
            | (self.properties & !InsnProperties::FLOW & !InsnProperties::FALL_THROUGH);
    }

    pub fn next_address(&self) -> Address {
        self.address + self.size as usize
    }

    pub fn call_target(&self) -> Option<Address> {
        self.flow_targets()
            .find_map(|target| target.kind().is_call().then_some(target.to()))
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

    pub(crate) fn resolve_flow(
        &mut self,
        language: &'static Language,
        size: usize,
        operations: &[RawPCodeOp],
    ) -> Result<(), InsnError> {
        *self = Self::from_resolved_flow(language, self.address, size, operations)?;
        Ok(())
    }

    pub fn remove_fall_through(&mut self) {
        self.targets.retain(|(_, target)| !target.is_fall_through());
        self.properties = InsnProperties::from_targets(&self.targets)
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
    pub(crate) fn from_targets(targets: &[(u16, InsnTarget)]) -> Self {
        let mut prop = Self::empty();

        for (_, target) in targets.iter() {
            match target {
                InsnTarget::IntraBlk(_, true) => prop |= Self::FALL_THROUGH,
                InsnTarget::IntraBlk(_, false) | InsnTarget::InterBlk(_) => prop |= Self::BRANCH,
                InsnTarget::Unresolved => prop |= Self::BRANCH | Self::INDIRECT,
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
    InterBlk(Address),
    InterRet(Option<Address>, bool),
    InterSub(Address),
    InterSubIndirect(Option<Address>),
    IntraBlk(Location, bool),
    IntraIns(Location, bool),
    Intrinsic,
    Unresolved,
}

impl InsnTarget {
    pub fn is_call(&self) -> bool {
        matches!(self, Self::InterSub(_) | Self::InterSubIndirect(_))
    }

    pub fn is_fall_through(&self) -> bool {
        matches!(self, Self::IntraIns(_, true) | Self::IntraBlk(_, true))
    }

    pub fn is_indirect(&self) -> bool {
        matches!(
            self,
            Self::InterSubIndirect(_) | Self::InterRet(None, _) | Self::Unresolved
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
            Self::IntraIns(location, _) | Self::IntraBlk(location, _) => Some(location.address()),
            Self::InterBlk(address)
            | Self::InterSub(address)
            | Self::InterSubIndirect(Some(address))
            | Self::InterRet(Some(address), _) => Some(*address),
            Self::InterSubIndirect(None)
            | Self::InterRet(None, _)
            | Self::Intrinsic
            | Self::Unresolved => None,
        }
    }

    fn resolved(&self) -> Option<(InsnTargetKind, Address)> {
        use InsnTarget::*;
        use InsnTargetKind::*;

        match *self {
            IntraBlk(taken, _) if taken.position() == 0 => Some((Local, taken.address())),
            InterBlk(taken) => Some((Local, taken)),
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
            Self::IntraBlk(loc, _) => write!(f, "intra-block flow to {loc}"),
            Self::InterBlk(tgt) => write!(f, "inter-block flow to {tgt}"),
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
            Self::Unresolved => write!(f, "unresolved"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::FlowKind;

    #[test]
    fn set_call_target_preserves_indirect_classification() -> Result<(), InsnError> {
        let address = Address::from(0x1000u64);
        let target = Address::from(0x2000u64);
        let mut insn = Insn::from_indirect_call(address, 4)?;

        insn.set_call_target(target);

        assert!(insn.is_indirect());
        assert_eq!(insn.call_target(), Some(target));
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
