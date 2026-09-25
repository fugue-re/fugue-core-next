use std::fmt;

use crate::context::ContextBitRange;
use crate::format::InstructionFormatter;
use crate::language::Language;
use crate::operand::{Operands, OperandsContext};
use crate::pcode::{LiftingContext, PCodeBuilderContext, PCodeOp, Varnode};

#[derive(Clone)]
pub struct Lifter {
    language: &'static Language,
    context: LiftingContext,
    operand_context: OperandsContext,
}

impl Lifter {
    pub fn new(language: &'static Language) -> Self {
        let context = LiftingContext::new(
            language,
            2,
            language.default_context(),
            language.unique_mask(),
        );
        Self {
            language,
            context,
            operand_context: OperandsContext::new(),
        }
    }

    pub fn with_context(language: &'static Language, context: LiftingContext) -> Self {
        debug_assert!(
            std::ptr::eq(context.language(), language),
            "lifter language and context language must match",
        );
        Self {
            language,
            context,
            operand_context: OperandsContext::new(),
        }
    }

    pub fn language(&self) -> &'static Language {
        self.language
    }

    pub fn context(&self) -> &LiftingContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut LiftingContext {
        &mut self.context
    }

    pub fn address_alignment(&self) -> usize {
        self.language.address_alignment()
    }

    pub fn address_bits(&self) -> u32 {
        self.language.address_bits()
    }

    pub fn address_size(&self) -> usize {
        self.language.address_size()
    }

    pub fn address_upper_bound(&self) -> u64 {
        self.language.address_upper_bound()
    }

    pub fn constant_space(&self) -> u8 {
        self.language.constant_space()
    }

    pub fn default_space(&self) -> u8 {
        self.language.default_space()
    }

    pub fn register_space(&self) -> u8 {
        self.language.register_space()
    }

    pub fn register_space_size(&self) -> usize {
        self.language.register_space_size()
    }

    pub fn unique_mask(&self) -> u64 {
        self.language.unique_mask()
    }

    pub fn unique_space(&self) -> u8 {
        self.language.unique_space()
    }

    pub fn unique_space_size(&self) -> usize {
        self.language.unique_space_size()
    }

    pub fn space_name(&self, space: u8) -> Option<&'static str> {
        self.language.space_name(space)
    }

    pub fn space_by_name(&self, name: impl AsRef<str>) -> Option<u8> {
        self.language.space_by_name(name.as_ref())
    }

    pub fn space_word_size(&self, space: u8) -> Option<usize> {
        self.language.space_word_size(space)
    }

    pub fn space_upper_bound(&self, space: u8) -> Option<u64> {
        self.language.space_upper_bound(space)
    }

    pub fn wrap_offset(&self, space: u8, offset: u64) -> Option<u64> {
        self.language.wrap_offset(space, offset)
    }

    pub fn context_variable_by_name(&self, name: impl AsRef<str>) -> Option<ContextBitRange> {
        self.language.context_variable_by_name(name)
    }

    pub fn register_by_name(&self, name: impl AsRef<str>) -> Option<Varnode> {
        self.language.register_by_name(name)
    }

    pub fn register_name(&self, vnd: &Varnode) -> Option<&'static str> {
        self.language.register_name(vnd)
    }

    pub fn user_op_by_name(&self, name: impl AsRef<str>) -> Option<u16> {
        self.language.user_op_by_name(name)
    }

    pub fn user_op_by_id(&self, id: u16) -> Option<&'static str> {
        self.language.user_op_by_id(id)
    }

    pub fn builder(&self) -> PCodeBuilderContext {
        self.language.builder()
    }

    pub fn resolve(
        &mut self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        apply_commits: bool,
    ) -> Option<usize> {
        self.language
            .resolve(address, bytes, &mut self.context, apply_commits)
    }

    pub fn operands(
        &mut self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        operands: &mut Operands,
    ) -> Option<usize> {
        self.language.operands(
            address,
            bytes,
            &mut self.context,
            &mut self.operand_context,
            operands,
        )
    }

    pub fn disassemble(
        &mut self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        disassembly: &mut String,
    ) -> Option<usize> {
        self.language
            .disassemble(address, bytes, &mut self.context, disassembly)
    }

    pub fn disassemble_and_format<F: InstructionFormatter + ?Sized>(
        &mut self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        formatter: &mut F,
    ) -> Result<Option<usize>, fmt::Error> {
        self.language
            .disassemble_and_format(address, bytes, &mut self.context, formatter)
    }

    pub fn disassemble_parts(
        &mut self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        mnemonic: &mut String,
        operands: &mut String,
    ) -> Option<usize> {
        self.language
            .disassemble_parts(address, bytes, &mut self.context, mnemonic, operands)
    }

    pub fn lift(
        &mut self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        operations: &mut Vec<PCodeOp>,
    ) -> Option<usize> {
        self.language
            .lift(address, bytes, &mut self.context, operations)
    }
}

pub type LifterFactory = fn() -> Lifter;
