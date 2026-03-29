use std::fmt;

use fugue_lifter::{Language, Op, PCodeOp};
use smallvec::SmallVec;

use crate::ir::{Address, Id, Location, ToAddress};
use crate::lifter::{Lifter, LifterError};

pub type InsnId = Id<Insn>;

// TODO: review the choice of Vec
pub type InsnList = Vec<Insn>;

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
    operations: Vec<PCodeOp>,
    targets: SmallVec<[(u16, InsnTarget); 2]>,
    length: u8,
}

impl Insn {
    pub(crate) fn from_lifted(
        language: &'static Language,
        address: Address,
        length: usize,
        operations: Vec<PCodeOp>,
    ) -> Self {
        let naddress = address + length;

        let targets = InsnTarget::from_lifted(language, address, naddress, &operations);

        let mut properties = InsnProperties::from_targets(&targets);
        if operations.is_empty() {
            properties |= InsnProperties::NOP;
        }

        properties |= InsnProperties::LIFTED;

        Self {
            address,
            properties,
            operations,
            targets,
            length: length
                .try_into()
                .expect("instruction length must not exceed 255 bytes"),
        }
    }

    pub(crate) fn from_disassembly(
        address: Address,
        length: usize,
        properties: InsnProperties,
    ) -> Self {
        Self {
            address,
            properties,
            operations: Vec::new(),
            targets: SmallVec::new(),
            length: length
                .try_into()
                .expect("instruction length must not exceed 255 bytes"),
        }
    }

    pub fn ensure_lifted(&mut self, lifter: &mut Lifter, bytes: &[u8]) -> Result<(), LifterError> {
        if self.is_lifted() {
            return Ok(());
        }

        self.operations.clear();
        self.targets.clear();

        let length = lifter.lift_into(self.address, bytes, &mut self.operations)?;

        self.length = length
            .try_into()
            .expect("instruction length must not exceed 255 bytes");

        let naddress = self.next_address();

        InsnTarget::from_lifted_into(
            lifter.language(),
            self.address,
            naddress,
            &self.operations,
            &mut self.targets,
        );

        self.properties = InsnProperties::from_targets(&self.targets) | InsnProperties::LIFTED;

        if self.operations.is_empty() {
            self.properties |= InsnProperties::NOP;
        }

        Ok(())
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

    pub fn mark_lifted(&mut self) {
        self.properties |= InsnProperties::LIFTED;
    }

    pub fn mark_needs_lifting(&mut self) {
        self.properties |= InsnProperties::NEEDS_LIFTING;
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

    pub fn is_lifted(&self) -> bool {
        self.properties().intersects(InsnProperties::LIFTED)
    }

    pub fn needs_lifting(&self) -> bool {
        self.properties().intersects(InsnProperties::NEEDS_LIFTING)
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

    pub fn display(&self, language: &'static Language) -> InsnFormatter {
        InsnFormatter::new(self, language)
    }
}

pub struct InsnFormatter<'a> {
    lifted: &'a Insn,
    language: &'static Language,
}

impl<'a> InsnFormatter<'a> {
    pub fn new(lifted: &'a Insn, language: &'static Language) -> Self {
        Self { lifted, language }
    }
}

impl fmt::Display for InsnFormatter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lifted = self.lifted;
        let language = self.language;

        if !lifted.is_lifted() {
            return write!(f, "<not lifted; length: {}>", lifted.len());
        }

        language.display(&lifted.operations).fmt(f)
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

        // instruction has been lifted
        const LIFTED        = 0b0010_0000_0000_0000;

        // instruction needs to be lifted
        const NEEDS_LIFTING = 0b0100_0000_0000_0000;

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
                InsnTarget::IntraBlk(_, false)
                | InsnTarget::InterBlk(_)
                | InsnTarget::Unresolved => prop |= Self::BRANCH,
                InsnTarget::InterSub(_) => prop |= Self::CALL,
                InsnTarget::InterRet(_, _) => prop |= Self::RETURN,
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
    pub(crate) fn from_lifted(
        language: &'static Language,
        address: Address,
        naddress: Address,
        opns: &[PCodeOp],
    ) -> SmallVec<[(u16, Self); 2]> {
        let mut targets = SmallVec::new();
        Self::from_lifted_into(language, address, naddress, opns, &mut targets);
        targets
    }

    fn from_lifted_into(
        language: &'static Language,
        address: Address,
        naddress: Address,
        opns: &[PCodeOp],
        targets: &mut SmallVec<[(u16, Self); 2]>,
    ) {
        let op_count = opns.len() as u16;

        let is_local = |loc: &Location| -> bool { loc.address() == address };
        let is_fall = |loc: &Location| -> bool { loc.address() == naddress };

        let nlocation = |i: u16| -> Location {
            if i >= op_count {
                Location::new(naddress, i - op_count)
            } else {
                Location::new(address, i)
            }
        };

        let ncall = |i: u16, loc: Option<Location>, targets: &mut SmallVec<[(u16, Self); 2]>| {
            let Some(loc) = loc else {
                targets.push((i, Self::InterSub(None)));
                return;
            };

            if loc.position() != 0 {
                targets.push((i, Self::IntraIns(loc, false)));
            } else {
                targets.push((i, Self::InterSub(Some(loc.address()))));
            }
        };

        let nbranch = |i: u16, loc: Option<Location>, targets: &mut SmallVec<[(u16, Self); 2]>| {
            let Some(loc) = loc else {
                targets.push((i, Self::Unresolved));
                return;
            };

            if is_local(&loc) {
                targets.push((i, Self::IntraIns(loc, false)));
            } else if is_fall(&loc) {
                targets.push((i, Self::IntraBlk(loc, false)));
            } else {
                targets.push((i, Self::InterBlk(loc.address())));
            }
        };

        let nfall = |i: u16, fall: Location, targets: &mut SmallVec<[(u16, Self); 2]>| {
            targets.push((
                i,
                if is_local(&fall) {
                    Self::IntraIns(fall, true)
                } else {
                    Self::IntraBlk(fall, true)
                },
            ));
        };

        if op_count == 0 {
            nfall(0, nlocation(1), targets);
            return;
        }

        for (i, stmt) in opns.iter().enumerate() {
            let i = i as u16;
            let next = nlocation(i + 1);
            let inputs = stmt.inputs();
            match stmt.op() {
                Op::Branch => {
                    let locn = Location::absolute_from(language, address, inputs[0], i);
                    nbranch(i, locn, targets);
                }
                Op::CBranch => {
                    let locn = Location::absolute_from(language, address, inputs[0], i);
                    nbranch(i, locn, targets);
                    nfall(i, next, targets);
                }
                Op::IBranch => {
                    nbranch(i, None, targets);
                }
                Op::Call => {
                    let locn = Location::absolute_from(language, address, inputs[0], i);
                    ncall(i, locn, targets);
                    nfall(i, next, targets);
                }
                Op::ICall => {
                    ncall(i, None, targets);
                    nfall(i, next, targets);
                }
                Op::Return => {
                    let addr = inputs[0].to_address(language);
                    targets.push((i, Self::InterRet(addr, i + 1 == op_count)));
                }
                Op::UserOp(_, _) => {
                    targets.push((i, Self::Intrinsic));
                    nfall(i, next, targets);
                }
                _ => {
                    if i + 1 == op_count {
                        nfall(i, next, targets);
                    }
                }
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
