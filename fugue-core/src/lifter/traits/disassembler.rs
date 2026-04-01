use crate::ir::{Insn, MetaAddress};
use crate::lifter::{DisassemblerError, LiftingContext};

pub trait Disassembler {
    fn disassemble(
        &mut self,
        address: MetaAddress,
        bytes: &[u8],
        context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError>;
}
