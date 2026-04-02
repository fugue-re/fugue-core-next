use crate::ir::{Address, Insn};
use crate::lifter::{DisassemblerError, LiftingContext};

pub trait Disassembler {
    fn disassemble(
        &mut self,
        address: Address,
        bytes: &[u8],
        context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError>;
}
