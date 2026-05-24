use std::fmt::{Debug, Display};
use std::str::FromStr;

use fugue_lifter::LifterBuilderError;
use fugue_lifter::runtime::context::ContextBitRange;
use fugue_lifter::runtime::language::Language;
use fugue_lifter::runtime::operand::Operands;
use fugue_lifter::runtime::pcode::{LiftingContext, Varnode};
use thiserror::Error;

use crate::il::pcode::PCodeOp;
use crate::ir::{Address, Insn, InsnProperties};
use crate::lifter::disassembler::DisassemblerError;
use crate::lifter::resolve_language;
use crate::lifter::traits::Disassembler;

#[derive(Debug, Error)]
pub enum LifterError {
    #[error(transparent)]
    Builder(#[from] LifterBuilderError),
    #[error("invalid instruction at {0}")]
    InvalidInstruction(Address),
    #[error(transparent)]
    Lifter(anyhow::Error),
}

impl LifterError {
    pub fn invalid_instruction(address: Address) -> Self {
        Self::InvalidInstruction(address)
    }

    pub fn disassembler<E>(error: E) -> Self
    where
        E: std::error::Error + Debug + Display + Send + Sync + 'static,
    {
        Self::Lifter(anyhow::Error::new(error))
    }

    pub fn disassembler_with<M>(msg: M) -> Self
    where
        M: Debug + Display + Send + Sync + 'static,
    {
        Self::Lifter(anyhow::Error::msg(msg))
    }
}

#[derive(Clone)]
pub struct Lifter(fugue_lifter::Lifter);

impl Lifter {
    pub fn new(language: &'static Language) -> Self {
        Self(fugue_lifter::Lifter::new(language))
    }

    pub fn with_context(language: &'static Language, context: LiftingContext) -> Self {
        Self(fugue_lifter::Lifter::with_context(language, context))
    }

    pub fn language(&self) -> &'static Language {
        self.0.language()
    }

    pub fn context(&self) -> &LiftingContext {
        self.0.context()
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        self.0.context_mut()
    }

    pub fn address_alignment(&self) -> usize {
        self.0.address_alignment()
    }

    pub fn address_bits(&self) -> u32 {
        self.0.address_bits()
    }

    pub fn address_size(&self) -> usize {
        self.0.address_size()
    }

    pub fn address_upper_bound(&self) -> u64 {
        self.0.address_upper_bound()
    }

    pub fn constant_space(&self) -> u8 {
        self.0.constant_space()
    }

    pub fn default_space(&self) -> u8 {
        self.0.default_space()
    }

    pub fn register_space(&self) -> u8 {
        self.0.register_space()
    }

    pub fn register_space_size(&self) -> usize {
        self.0.register_space_size()
    }

    pub fn unique_mask(&self) -> u64 {
        self.0.unique_mask()
    }

    pub fn unique_space(&self) -> u8 {
        self.0.unique_space()
    }

    pub fn unique_space_size(&self) -> usize {
        self.0.unique_space_size()
    }

    pub fn space_name(&self, space: u8) -> Option<&'static str> {
        self.0.space_name(space)
    }

    pub fn space_by_name(&self, name: impl AsRef<str>) -> Option<u8> {
        self.0.space_by_name(name)
    }

    pub fn space_word_size(&self, space: u8) -> Option<usize> {
        self.0.space_word_size(space)
    }

    pub fn space_upper_bound(&self, space: u8) -> Option<u64> {
        self.0.space_upper_bound(space)
    }

    pub fn wrap_offset(&self, space: u8, offset: u64) -> Option<u64> {
        self.0.wrap_offset(space, offset)
    }

    pub fn context_variable_by_name(&self, name: impl AsRef<str>) -> Option<ContextBitRange> {
        self.0.context_variable_by_name(name)
    }

    pub fn register_by_name(&self, name: impl AsRef<str>) -> Option<Varnode> {
        self.0.register_by_name(name)
    }

    pub fn register_name(&self, vnd: &Varnode) -> Option<&'static str> {
        self.0.register_name(vnd)
    }

    pub fn user_op_by_name(&self, name: impl AsRef<str>) -> Option<u16> {
        self.0.user_op_by_name(name)
    }

    pub fn user_op_by_id(&self, id: u16) -> Option<&'static str> {
        self.0.user_op_by_id(id)
    }

    pub fn resolve(
        &mut self,
        address: impl Into<Address>,
        bytes: &[u8],
        apply_commits: bool,
    ) -> Option<usize> {
        let address = address.into();
        self.0.resolve(address.offset(), bytes, apply_commits)
    }

    pub fn operands(&mut self, address: impl Into<Address>, bytes: &[u8]) -> Option<Operands> {
        let address = address.into();
        let mut operands = Operands::new();
        self.0.operands(address.offset(), bytes, &mut operands)?;
        Some(operands)
    }

    pub fn operands_into(
        &mut self,
        address: impl Into<Address>,
        bytes: &[u8],
        operands: &mut Operands,
    ) -> Option<usize> {
        let address = address.into();
        self.0.operands(address.offset(), bytes, operands)
    }

    pub fn disassemble(
        &mut self,
        address: impl Into<Address>,
        bytes: &[u8],
        output: &mut String,
    ) -> Option<usize> {
        let address = address.into();
        self.0.disassemble(address.offset(), bytes, output)
    }

    pub fn disassemble_parts(
        &mut self,
        address: impl Into<Address>,
        bytes: &[u8],
        mnemonic: &mut String,
        operands: &mut String,
    ) -> Option<usize> {
        let address = address.into();
        self.0
            .disassemble_parts(address.offset(), bytes, mnemonic, operands)
    }

    pub fn lift(&mut self, address: impl Into<Address>, bytes: &[u8]) -> Result<Insn, LifterError> {
        let address = address.into();
        let mut operations = Vec::new();

        let length = self.lift_into(address, bytes, &mut operations)?;

        Ok(Insn::from_lifted(
            self.language(),
            address,
            length,
            operations,
        ))
    }

    pub fn lift_into(
        &mut self,
        addr: impl Into<Address>,
        bytes: &[u8],
        output: &mut Vec<PCodeOp>,
    ) -> Result<usize, LifterError> {
        let address = addr.into();
        let Some(length) = self.0.lift(address.offset(), bytes, output) else {
            return Err(LifterError::InvalidInstruction(address));
        };

        Ok(length)
    }
}

impl FromStr for Lifter {
    type Err = LifterBuilderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        resolve_language(s)
            .map(Lifter::new)
            .map_err(|_| LifterBuilderError::Unsupported)
    }
}

impl Disassembler for Lifter {
    fn disassemble(
        &mut self,
        address: Address,
        bytes: &[u8],
        _context: &mut LiftingContext,
    ) -> Result<Insn, DisassemblerError> {
        let Some(size) = self.resolve(address, bytes, true) else {
            return Err(DisassemblerError::InvalidInstruction(address));
        };

        Ok(Insn::from_disassembly(
            address,
            size,
            InsnProperties::NEEDS_LIFTING,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn x86_64_lifter() -> Lifter {
        #[cfg(feature = "static-lifters")]
        {
            "x86:LE:64".parse::<Lifter>().unwrap()
        }
        #[cfg(not(feature = "static-lifters"))]
        {
            use std::path::PathBuf;

            use fugue_sleigh_language::LanguageDB;

            use crate::lifter::LanguageLoader;

            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("x86_LE_64_default.flift");
            let loader = LanguageLoader::from(LanguageDB::default());
            loader.load_from(path).map(Lifter::new).unwrap()
        }
    }

    #[test]
    fn test_basic_operands() {
        let mut lifter = x86_64_lifter();
        let bytes = [0x48, 0x89, 0xd8]; // mov rax, rbx

        let operands = lifter.operands(0x1000, &bytes).unwrap();
        assert_eq!(operands.len(), 2);

        let op0 = operands.get(0).unwrap();
        assert_eq!(op0.range().cloned(), Some(21..24));

        let op1 = operands.get(1).unwrap();
        assert_eq!(op1.range().cloned(), Some(18..21));
    }

    #[test]
    fn test_grouped_operands() {
        let mut lifter = x86_64_lifter();

        // mov rax, [0x1000]
        let bytes = [0x48, 0x8b, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00];

        let operands = lifter.operands(0x1000, &bytes).unwrap();
        assert_eq!(operands.len(), 2);

        let op0 = operands.get(0).unwrap();
        assert_eq!(op0.range().cloned(), Some(18..21));

        let op1 = operands.get(1).unwrap();
        assert_eq!(op1.range().cloned(), Some(32..64));

        // mov rax, [ecx*4 + 0x10]
        let bytes = [0x67, 0x48, 0x8b, 0x04, 0x8d, 0x10, 0x00, 0x00, 0x00];

        let operands = lifter.operands(0x1000, &bytes).unwrap();
        assert_eq!(operands.len(), 2);

        let op0 = operands.get(0).unwrap();
        assert_eq!(op0.symbol(), Some("RAX"));

        let op1 = operands.get(1).unwrap();
        assert!(op1.group().is_some());

        let op1_0 = op1.group().unwrap().get(0).unwrap();
        assert_eq!(op1_0.symbol(), Some("ECX"));

        let op1_1 = op1.group().unwrap().get(1).unwrap();
        assert_eq!(op1_1.value(), Some(4));

        let op1_2 = op1.group().unwrap().get(2).unwrap();
        assert_eq!(op1_2.value(), Some(0x10));
    }
}
