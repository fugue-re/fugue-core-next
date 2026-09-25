use fugue_sleigh_language::convention as sleigh;
use fugue_sleigh_language::varnode::VarnodeData;

use crate::convention;
use crate::dynamic::install::Install;
use crate::pcode::Varnode;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum ReturnAddress {
    Register(Varnode),
    StackRelative { offset: u64, size: usize },
}

impl From<&sleigh::ReturnAddress> for ReturnAddress {
    fn from(return_address: &sleigh::ReturnAddress) -> Self {
        match return_address {
            sleigh::ReturnAddress::Register { varnode, .. } => {
                Self::Register(PrototypeOperand::varnode(varnode))
            }
            sleigh::ReturnAddress::StackRelative { offset, size } => Self::StackRelative {
                offset: *offset,
                size: *size,
            },
        }
    }
}

impl Install for ReturnAddress {
    type Target = convention::ReturnAddress;

    fn install(self) -> Self::Target {
        match self {
            Self::Register(varnode) => convention::ReturnAddress::Register(varnode),
            Self::StackRelative { offset, size } => {
                convention::ReturnAddress::StackRelative { offset, size }
            }
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct Convention {
    name: Box<str>,
    stack_pointer: Varnode,
    return_address: Option<ReturnAddress>,
    prototypes: Box<[Prototype]>,
}

impl From<&sleigh::Convention> for Convention {
    fn from(convention: &sleigh::Convention) -> Self {
        Self {
            name: Box::<str>::from(convention.name()),
            stack_pointer: PrototypeOperand::varnode(convention.stack_pointer().varnode()),
            return_address: convention.return_address().map(Into::into),
            prototypes: convention.prototypes().map(Into::into).collect(),
        }
    }
}

impl Install for Convention {
    type Target = convention::Convention;

    fn install(self) -> Self::Target {
        let mut convention = convention::Convention::new(self.name.install(), self.stack_pointer)
            .with_prototypes(self.prototypes.install());
        if let Some(return_address) = self.return_address {
            convention = convention.with_return_address(return_address.install());
        }
        convention
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum PrototypeOperand {
    Register(Varnode),
    RegisterJoin(Varnode, Varnode),
    StackRelative(u64),
}

impl PrototypeOperand {
    fn varnode(varnode: &VarnodeData) -> Varnode {
        Varnode::new(
            u8::try_from(varnode.space().index()).expect("address-space identifier fits in u8"),
            varnode.offset(),
            u16::try_from(varnode.size()).expect("register size fits in u16"),
        )
    }
}

impl From<&sleigh::PrototypeOperand> for PrototypeOperand {
    fn from(operand: &sleigh::PrototypeOperand) -> Self {
        match operand {
            sleigh::PrototypeOperand::Register { varnode, .. } => {
                Self::Register(Self::varnode(varnode))
            }
            sleigh::PrototypeOperand::RegisterJoin {
                first_varnode,
                second_varnode,
                ..
            } => Self::RegisterJoin(Self::varnode(first_varnode), Self::varnode(second_varnode)),
            sleigh::PrototypeOperand::StackRelative(offset) => Self::StackRelative(*offset),
        }
    }
}

impl Install for PrototypeOperand {
    type Target = convention::PrototypeOperand;

    fn install(self) -> Self::Target {
        match self {
            Self::Register(varnode) => convention::PrototypeOperand::Register(varnode),
            Self::RegisterJoin(first, second) => {
                convention::PrototypeOperand::RegisterJoin(first, second)
            }
            Self::StackRelative(offset) => convention::PrototypeOperand::StackRelative(offset),
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct PrototypeEntry {
    min_size: usize,
    max_size: usize,
    alignment: u64,
    meta_type: Option<Box<str>>,
    extension: Option<Box<str>>,
    operand: PrototypeOperand,
}

impl From<&sleigh::PrototypeEntry> for PrototypeEntry {
    fn from(entry: &sleigh::PrototypeEntry) -> Self {
        Self {
            min_size: entry.min_size(),
            max_size: entry.max_size(),
            alignment: entry.alignment(),
            meta_type: entry.meta_type().as_deref().map(Box::<str>::from),
            extension: entry.extension().as_deref().map(Box::<str>::from),
            operand: entry.operand().into(),
        }
    }
}

impl Install for PrototypeEntry {
    type Target = convention::PrototypeEntry;

    fn install(self) -> Self::Target {
        let mut entry = convention::PrototypeEntry::new(
            self.min_size,
            self.max_size,
            self.alignment,
            self.operand.install(),
        );
        if let Some(meta_type) = self.meta_type {
            entry = entry.with_meta_type(meta_type.install());
        }
        if let Some(extension) = self.extension {
            entry = entry.with_extension(extension.install());
        }
        entry
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct Prototype {
    name: Box<str>,
    extra_pop: u64,
    stack_shift: u64,
    inputs: Box<[PrototypeEntry]>,
    outputs: Box<[PrototypeEntry]>,
    unaffected: Box<[PrototypeOperand]>,
    killed_by_call: Box<[PrototypeOperand]>,
    likely_trashed: Box<[PrototypeOperand]>,
}

impl From<&sleigh::Prototype> for Prototype {
    fn from(prototype: &sleigh::Prototype) -> Self {
        Self {
            name: Box::<str>::from(prototype.name()),
            extra_pop: prototype.extra_pop(),
            stack_shift: prototype.stack_shift(),
            inputs: prototype.inputs().iter().map(Into::into).collect(),
            outputs: prototype.outputs().iter().map(Into::into).collect(),
            unaffected: prototype.unaffected().iter().map(Into::into).collect(),
            killed_by_call: prototype.killed_by_call().iter().map(Into::into).collect(),
            likely_trashed: prototype.likely_trashed().iter().map(Into::into).collect(),
        }
    }
}

impl Install for Prototype {
    type Target = convention::Prototype;

    fn install(self) -> Self::Target {
        convention::Prototype::new(self.name.install(), self.extra_pop, self.stack_shift)
            .with_inputs(self.inputs.install())
            .with_outputs(self.outputs.install())
            .with_unaffected(self.unaffected.install())
            .with_killed_by_call(self.killed_by_call.install())
            .with_likely_trashed(self.likely_trashed.install())
    }
}
