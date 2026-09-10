use thiserror::Error;

use crate::arch::Arch;
use crate::ir::{Address, Insn, InsnError};
use crate::lifter::{
    Disassembler, DisassemblerError, Lifter, LifterError, LiftingContext, RawPCodeOp,
};

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

    pub(crate) fn into_insn(self) -> Insn {
        self.insn
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

    pub(crate) fn context(&self) -> &LiftingContext {
        self.lifter.context()
    }

    pub(crate) fn context_mut(&mut self) -> &mut LiftingContext {
        self.lifter.context_mut()
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
        let indirect_target = insn
            .indirect_target_pointer(language, &self.operations)
            .map(|pointer| IndirectTarget {
                pointer,
                size: language.address_size(),
                big_endian: language.is_big_endian(),
            });

        Ok(ResolvedInsn {
            insn,
            indirect_target,
        })
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
}
