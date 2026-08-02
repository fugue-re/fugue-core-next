use thiserror::Error;

use crate::arch::Arch;
use crate::ir::{Address, Insn, InsnError, InsnList};
use crate::lifter::{
    ContextSet, Disassembler, DisassemblerError, Language, Lifter, LifterError, LiftingContext, Op,
    RawPCodeOp,
};

#[derive(Debug, Error)]
pub enum InsnExtentError {
    #[error(
        "instruction extent at {address} requires {required} contiguous bytes, but only {available} are available"
    )]
    InsufficientBytes {
        address: Address,
        available: usize,
        required: usize,
    },
    #[error("instruction at {address} has size {size}, with {remaining} extent bytes remaining")]
    InvalidInsnSize {
        address: Address,
        size: usize,
        remaining: usize,
    },
    #[error(transparent)]
    Resolution(#[from] InsnResolverError),
}

impl InsnExtentError {
    pub(crate) const fn insufficient_bytes(
        address: Address,
        available: usize,
        required: usize,
    ) -> Self {
        Self::InsufficientBytes {
            address,
            available,
            required,
        }
    }

    pub(crate) const fn invalid_insn_size(address: Address, size: usize, remaining: usize) -> Self {
        Self::InvalidInsnSize {
            address,
            size,
            remaining,
        }
    }
}

#[derive(Debug, Error)]
pub enum InsnResolverError {
    #[error(transparent)]
    Disassembly(#[from] DisassemblerError),
    #[error(transparent)]
    Insn(#[from] InsnError),
    #[error(transparent)]
    Lifting(#[from] LifterError),
}

pub(crate) struct InsnResolver {
    disassembler: Disassembler,
    lifter: Lifter,
    operations: Vec<RawPCodeOp>,
}

struct IndirectTarget {
    pointer: Address,
    size: usize,
    big_endian: bool,
}

pub(crate) struct ResolvedInsn {
    insn: Insn,
    indirect_target: Option<IndirectTarget>,
}

impl ResolvedInsn {
    pub(crate) fn into_insn(self) -> Insn {
        self.insn
    }

    pub(crate) fn resolve_indirect_target(
        &self,
        mut read: impl FnMut(Address, &mut [u8]) -> bool,
    ) -> Option<Address> {
        let target = self.indirect_target.as_ref()?;
        let mut buffer = [0u8; size_of::<u64>()];
        let bytes = buffer.get_mut(..target.size)?;
        if !read(target.pointer, bytes) {
            return None;
        }

        let offset = if target.big_endian {
            bytes
                .iter()
                .fold(0u64, |value, &byte| (value << 8) | u64::from(byte))
        } else {
            bytes
                .iter()
                .rev()
                .fold(0u64, |value, &byte| (value << 8) | u64::from(byte))
        };

        Some(Address::new(target.pointer.space(), offset))
    }
}

impl AsRef<Insn> for ResolvedInsn {
    fn as_ref(&self) -> &Insn {
        &self.insn
    }
}

impl InsnResolver {
    pub(crate) fn new(arch: &Arch) -> Self {
        Self {
            disassembler: arch.disassembler(),
            lifter: arch.lifter(),
            operations: Vec::new(),
        }
    }

    pub(crate) fn resolve(
        &mut self,
        address: Address,
        bytes: impl AsRef<[u8]>,
    ) -> Result<ResolvedInsn, InsnResolverError> {
        let bytes = bytes.as_ref();
        self.operations.clear();
        let mut insn = self
            .disassembler
            .disassemble(address, bytes, self.lifter.context_mut())?;

        if insn.needs_flow_resolution() || insn.size() == 0 {
            let size = self.lifter.lift(address, bytes, &mut self.operations)?;
            insn.resolve_flow(self.lifter.language(), size, &self.operations)?;
        }

        let language = self.lifter.language();
        let indirect_target =
            Self::indirect_target_pointer(language, &insn, &self.operations).map(|pointer| {
                IndirectTarget {
                    pointer,
                    size: language.address_size(),
                    big_endian: language.is_big_endian(),
                }
            });

        Ok(ResolvedInsn {
            insn,
            indirect_target,
        })
    }

    pub(crate) fn resolve_extent(
        &mut self,
        address: Address,
        size: usize,
        context: &ContextSet,
        bytes: &[u8],
    ) -> Result<InsnList, InsnExtentError> {
        let bytes = bytes
            .get(..size)
            .ok_or_else(|| InsnExtentError::insufficient_bytes(address, bytes.len(), size))?;
        context.apply(address, self.context_mut());

        let mut insns = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let insn_address = address + offset;
            let remaining = bytes.len() - offset;
            let insn = self.resolve(insn_address, &bytes[offset..])?.into_insn();
            let insn_size = insn.size();
            if insn_size == 0 || insn_size > remaining {
                return Err(InsnExtentError::invalid_insn_size(
                    insn_address,
                    insn_size,
                    remaining,
                ));
            }
            insns.push(insn);
            offset += insn_size;
        }

        Ok(insns)
    }

    pub(crate) fn lift_into(
        &mut self,
        address: Address,
        bytes: impl AsRef<[u8]>,
        output: &mut Vec<RawPCodeOp>,
    ) -> Result<usize, InsnResolverError> {
        self.operations.clear();
        let size = self
            .lifter
            .lift(address, bytes.as_ref(), &mut self.operations)?;
        output.append(&mut self.operations);
        Ok(size)
    }

    pub(crate) fn context(&self) -> &LiftingContext {
        self.lifter.context()
    }

    pub(crate) fn context_mut(&mut self) -> &mut LiftingContext {
        self.lifter.context_mut()
    }

    fn indirect_target_pointer(
        language: &Language,
        insn: &Insn,
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

        if language.in_default_space(&target) {
            return Some(Address::new(insn.address().space(), target.offset()));
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
            .filter(|source| language.in_default_space(source))
            .map(|source| Address::new(insn.address().space(), source.offset()))
    }
}
