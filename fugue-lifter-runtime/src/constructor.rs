use std::fmt::{self, Debug};

use crate::context::{ContextPostAction, ContextPreAction};
use crate::format::{
    InstructionFormatError, InstructionParts, InstructionSection, InstructionText,
    InstructionWriter,
};
use crate::input::{ContextCommit, FixedHandle, INVALID_HANDLE};
use crate::language::{Language, LanguageData};
use crate::operand::{Operand, OperandHandleResolver, OperandPiece, OperandResolver, Operands};
use crate::pcode::LiftingContextState;
use crate::template::handle_tpl;

pub struct Constructor {
    pub id: u16,
    pub context_pre_actions: &'static [ContextPreAction],
    pub context_post_actions: &'static [ContextPostAction],
    pub operands: &'static [Operand],
    pub result: Option<u16>,
    pub build_action: Option<u16>,
    pub print_pieces: &'static [PrintPiece],
    pub first_whitespace: Option<usize>,
    pub flow_through_index: Option<usize>,
    pub delay_slot_length: usize,
    pub minimum_length: usize,
}

pub enum PrintPiece {
    Operand(u16),
    Token(&'static str),
}

impl Debug for Constructor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Constructor{}", self.id)
    }
}

impl PartialEq for Constructor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Constructor {}

impl Constructor {
    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn apply_context_actions(
        &'static self,
        data: &'static LanguageData,
        state: &mut LiftingContextState,
    ) -> Option<()> {
        unsafe {
            for action in self.context_pre_actions {
                action.apply(data, state)?;
            }

            for action in self.context_post_actions {
                let value = action.extract(state);
                let commit = ContextCommit {
                    action,
                    point: state.input().point,
                    value,
                };
                state.input().register_context_commit(commit);
            }

            Some(())
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn resolve_operands(
        &'static self,
        data: &'static LanguageData,
        state: &mut LiftingContextState,
    ) -> Option<()> {
        unsafe {
            state.input().set_constructor(self);

            self.apply_context_actions(data, state)?;

            if self.operands.is_empty() {
                state
                    .input()
                    .calculate_length(self.minimum_length, self.operands.len());
                state.input().pop_operand();

                if self.delay_slot_length > 0 {
                    state.input().set_delay_slot_length(self.delay_slot_length);
                }

                return Some(());
            }

            state.input().allocate_operands(self.operands.len())?;

            'outer: while !state.input().resolved() {
                let ctor = state.input().constructor();
                let opid = state.input().operand();

                for (i, opnd) in ctor.operands.iter().enumerate().skip(opid) {
                    let offset = opnd
                        .offset_base
                        .map(|n| state.input().offset_for_operand(n))
                        .unwrap_or_else(|| state.input().offset())
                        + opnd.offset_rela;

                    state.input().push_operand(i);
                    state.input().set_offset(offset);

                    match opnd.resolver {
                        OperandResolver::None => (),
                        OperandResolver::Filter(filter) => {
                            data.operand_filters[filter as usize].validate(data, state)?;
                        }
                        OperandResolver::Constructor(id) => {
                            let ctor = data.resolve_constructor(id, state)?;

                            state.input().set_constructor(ctor);

                            ctor.apply_context_actions(data, state)?;

                            if !ctor.operands.is_empty() {
                                state.input().allocate_operands(ctor.operands.len())?;
                            }

                            continue 'outer;
                        }
                    }

                    state.input().set_current_length(opnd.minimum_length);
                    state.input().pop_operand();
                }

                state
                    .input()
                    .calculate_length(ctor.minimum_length, ctor.operands.len());
                state.input().pop_operand();

                if ctor.delay_slot_length > 0 {
                    state.input().set_delay_slot_length(ctor.delay_slot_length);
                }
            }

            Some(())
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn resolve_handles(
        &'static self,
        data: &'static LanguageData,
        state: &mut LiftingContextState,
    ) -> Option<()> {
        unsafe {
            state.input().base_state();

            'outer: while !state.input().resolved() {
                let ctor = state.input().constructor();
                let opid = state.input().operand();

                for (i, opnd) in ctor.operands.iter().enumerate().skip(opid) {
                    state.input().push_operand(i);

                    match opnd.handle_resolver {
                        OperandHandleResolver::None => {
                            continue 'outer;
                        }
                        OperandHandleResolver::Symbol(symbol) => {
                            let handle =
                                data.symbols[symbol as usize].resolve_handle(data, state)?;
                            state.input().set_parent_handle(handle);
                        }
                        OperandHandleResolver::Expression(ref expr) => {
                            let offset = expr.resolve(data, state)? as u64;

                            if let Some(handle) = state.input().parent_handle_mut() {
                                handle.space = 0;
                                handle.offset_space = INVALID_HANDLE;
                                handle.offset_offset = offset;
                                handle.size = 0;
                            } else {
                                state.input().set_parent_handle(FixedHandle {
                                    space: 0,
                                    offset_offset: offset,
                                    ..Default::default()
                                });
                            }
                        }
                    }

                    state.input().pop_operand();
                }

                if let Some(tmpl) = ctor.result {
                    let handle = handle_tpl(data, tmpl).build(data, state)?;
                    state.input().set_parent_handle(handle);
                }

                state.input().pop_operand();
            }

            Some(())
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub(crate) unsafe fn format_mnemonic<W: fmt::Write>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        writer: &mut W,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            let mut writer = InstructionText::new(writer);
            self.write_mnemonic(language, state, &mut writer)
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub(crate) unsafe fn format_body<W: fmt::Write>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        writer: &mut W,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            let mut writer = InstructionText::new(writer);
            self.write_body(language, state, &mut writer)
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub(crate) unsafe fn format<W: fmt::Write>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        writer: &mut W,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            let mut writer = InstructionText::new(writer);
            self.format_instruction(language, state, &mut writer)
        }
    }

    pub(crate) unsafe fn format_parts<M: fmt::Write, O: fmt::Write>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        mnemonic: &mut M,
        operands: &mut O,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            let mut writer = InstructionParts::new(mnemonic, operands);
            self.format_instruction(language, state, &mut writer)
        }
    }

    pub(crate) unsafe fn format_instruction<O: InstructionWriter + ?Sized>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        output: &mut O,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            self.write_mnemonic(language, state, output)?;
            self.write_body(language, state, output)?;
            output.finish_instruction()?;
            Ok(())
        }
    }

    pub(crate) unsafe fn operands(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        operands: &mut Operands,
    ) -> Option<()> {
        unsafe { self.format_instruction(language, state, operands).ok() }
    }

    unsafe fn write_mnemonic<O: InstructionWriter + ?Sized>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        output: &mut O,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            if let Some(index) = self.flow_through_index
                && matches!(
                    &self.operands[index].handle_resolver,
                    OperandHandleResolver::None
                )
            {
                state.input().push_operand(index);
                let result = state
                    .input()
                    .constructor()
                    .write_mnemonic(language, state, output);
                state.input().pop_operand();
                return result;
            }

            let Some(pieces) = self
                .print_pieces
                .get(..self.first_whitespace.unwrap_or(self.print_pieces.len()))
            else {
                return Ok(());
            };

            self.write_pieces(
                language,
                state,
                output,
                pieces,
                InstructionSection::Mnemonic,
            )
        }
    }

    unsafe fn write_body<O: InstructionWriter + ?Sized>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        output: &mut O,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            if let Some(index) = self.flow_through_index
                && matches!(
                    &self.operands[index].handle_resolver,
                    OperandHandleResolver::None
                )
            {
                state.input().push_operand(index);
                let result = state
                    .input()
                    .constructor()
                    .write_body(language, state, output);
                state.input().pop_operand();
                return result;
            }

            let Some(pieces) = self
                .first_whitespace
                .and_then(|start| self.print_pieces.get(start + 1..))
            else {
                return Ok(());
            };

            if !pieces.is_empty() {
                output.write_separator(" ")?;
            }

            for piece in pieces {
                match piece {
                    PrintPiece::Operand(index) => {
                        self.write_operand(
                            language,
                            state,
                            output,
                            *index as usize,
                            InstructionSection::Operand,
                        )?;
                    }
                    PrintPiece::Token(token) => {
                        output.write_separator(token)?;
                    }
                }
            }

            Ok(())
        }
    }

    unsafe fn write_pieces<O: InstructionWriter + ?Sized>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        output: &mut O,
        pieces: &[PrintPiece],
        section: InstructionSection,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            for piece in pieces {
                match piece {
                    PrintPiece::Operand(index) => {
                        self.write_operand(language, state, output, *index as usize, section)?;
                    }
                    PrintPiece::Token(token) => {
                        section.write(output, OperandPiece::Text(token), None)?;
                    }
                }
            }

            Ok(())
        }
    }

    unsafe fn write_operand<O: InstructionWriter + ?Sized>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        output: &mut O,
        index: usize,
        section: InstructionSection,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            if matches!(section, InstructionSection::Operand) {
                output.begin_operand()?;
            }

            state.input().push_operand(index);
            let data = language.data();
            let result = match &self.operands[index].handle_resolver {
                OperandHandleResolver::None => {
                    let constructor = state.input().constructor();
                    constructor.write_pieces(
                        language,
                        state,
                        output,
                        constructor.print_pieces,
                        section,
                    )
                }
                OperandHandleResolver::Symbol(symbol) => {
                    data.symbols[*symbol as usize].operand_pieces(language, state, output, section)
                }
                OperandHandleResolver::Expression(expression) => {
                    expression.operand_pieces(language, state, output, section)
                }
            };
            state.input().pop_operand();
            result?;

            if matches!(section, InstructionSection::Operand) {
                output.end_operand()?;
            }

            Ok(())
        }
    }
}
