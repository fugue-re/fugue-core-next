use std::fmt::{self, Debug};

use crate::context::{ContextPostAction, ContextPreAction};
use crate::input::{ContextCommit, FixedHandle, INVALID_HANDLE};
use crate::language::LanguageData;
use crate::operand::{Operand, OperandHandleResolver, OperandResolver, Operands};
use crate::pcode::LiftingContextState;
use crate::symbol::Symbol;
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

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn resolve_operands(
        &'static self,
        data: &'static LanguageData,
        state: &mut LiftingContextState,
    ) -> Option<()> {
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

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn resolve_handles(
        &'static self,
        data: &'static LanguageData,
        state: &mut LiftingContextState,
    ) -> Option<()> {
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
                        let handle = data.symbols[symbol as usize].resolve_handle(data, state)?;
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

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn format_mnemonic<W: fmt::Write>(
        &self,
        data: &'static LanguageData,
        state: &mut LiftingContextState<'_>,
        writer: &mut W,
    ) -> fmt::Result {
        if let Some(index) = self.flow_through_index {
            if matches!(
                &self.operands[index].handle_resolver,
                OperandHandleResolver::None
            ) {
                state.input().push_operand(index);
                state
                    .input()
                    .constructor()
                    .format_mnemonic(data, state, writer)?;
                state.input().pop_operand();
                return Ok(());
            }
        }

        let Some(pieces) = self
            .print_pieces
            .get(..self.first_whitespace.unwrap_or(self.print_pieces.len()))
        else {
            return Ok(());
        };

        for p in pieces {
            match p {
                PrintPiece::Operand(index) => match &self.operands[*index as usize].handle_resolver
                {
                    OperandHandleResolver::None => {
                        state.input().push_operand(*index as usize);
                        state.input().constructor().format(data, state, writer)?;
                        state.input().pop_operand();
                    }
                    OperandHandleResolver::Symbol(symbol) => {
                        Symbol::format(&data.symbols[*symbol as usize], data, state, writer)?;
                    }
                    OperandHandleResolver::Expression(expr) => {
                        expr.format(data, state, writer)?;
                    }
                },
                PrintPiece::Token(token) => {
                    writer.write_str(token)?;
                }
            }
        }

        Ok(())
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn format_body<W: fmt::Write>(
        &self,
        data: &'static LanguageData,
        state: &mut LiftingContextState<'_>,
        writer: &mut W,
    ) -> Result<(), fmt::Error> {
        if let Some(index) = self.flow_through_index {
            if matches!(
                &self.operands[index].handle_resolver,
                OperandHandleResolver::None
            ) {
                state.input().push_operand(index);
                state
                    .input()
                    .constructor()
                    .format_body(data, state, writer)?;
                state.input().pop_operand();
                return Ok(());
            }
        }

        let Some(pieces) = self
            .first_whitespace
            .and_then(|start| self.print_pieces.get(start + 1..))
        else {
            return Ok(());
        };

        if !pieces.is_empty() {
            writer.write_char(' ')?;
        }

        for p in pieces {
            match p {
                PrintPiece::Operand(index) => match &self.operands[*index as usize].handle_resolver
                {
                    OperandHandleResolver::None => {
                        state.input().push_operand(*index as usize);
                        state.input().constructor().format(data, state, writer)?;
                        state.input().pop_operand();
                    }
                    OperandHandleResolver::Symbol(symbol) => {
                        Symbol::format(&data.symbols[*symbol as usize], data, state, writer)?;
                    }
                    OperandHandleResolver::Expression(expr) => {
                        expr.format(data, state, writer)?;
                    }
                },
                PrintPiece::Token(token) => {
                    writer.write_str(token)?;
                }
            }
        }

        Ok(())
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn format<W: fmt::Write>(
        &self,
        data: &'static LanguageData,
        state: &mut LiftingContextState<'_>,
        writer: &mut W,
    ) -> Result<(), fmt::Error> {
        for p in self.print_pieces {
            match p {
                PrintPiece::Operand(index) => {
                    state.input().push_operand(*index as usize);
                    match &self.operands[*index as usize].handle_resolver {
                        OperandHandleResolver::None => {
                            state.input().constructor().format(data, state, writer)?;
                        }
                        OperandHandleResolver::Symbol(symbol) => {
                            Symbol::format(&data.symbols[*symbol as usize], data, state, writer)?;
                        }
                        OperandHandleResolver::Expression(expr) => {
                            expr.format(data, state, writer)?;
                        }
                    }
                    state.input().pop_operand();
                }
                PrintPiece::Token(token) => {
                    writer.write_str(token)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) unsafe fn operands(
        &self,
        data: &'static LanguageData,
        state: &mut LiftingContextState<'_>,
        operands: &mut Operands,
    ) -> Option<()> {
        if let Some(index) = self.flow_through_index {
            if matches!(
                &self.operands[index].handle_resolver,
                OperandHandleResolver::None
            ) {
                state.input().push_operand(index);
                state
                    .input()
                    .constructor()
                    .operands(data, state, operands)?;
                state.input().pop_operand();
                return Some(());
            }
        }

        let Some(pieces) = self
            .first_whitespace
            .and_then(|start| self.print_pieces.get(start + 1..))
        else {
            return Some(());
        };

        for p in pieces {
            if let PrintPiece::Operand(index) = p {
                match &self.operands[*index as usize].handle_resolver {
                    OperandHandleResolver::None => {
                        let mut inner = Operands::new();
                        state.input().push_operand(*index as usize);
                        state
                            .input()
                            .constructor()
                            .operands_inner(data, state, &mut inner)?;
                        state.input().pop_operand();
                        operands.append(inner);
                    }
                    OperandHandleResolver::Symbol(symbol) => {
                        data.symbols[*symbol as usize].operands(data, state, operands);
                    }
                    OperandHandleResolver::Expression(expr) => {
                        expr.operands(data, state, operands);
                    }
                }
            }
        }

        Some(())
    }

    pub(crate) unsafe fn operands_inner(
        &self,
        data: &'static LanguageData,
        state: &mut LiftingContextState<'_>,
        operands: &mut Operands,
    ) -> Option<()> {
        for p in self.print_pieces {
            if let PrintPiece::Operand(index) = p {
                state.input().push_operand(*index as usize);
                match &self.operands[*index as usize].handle_resolver {
                    OperandHandleResolver::None => {
                        let mut inner = Operands::new();
                        state
                            .input()
                            .constructor()
                            .operands_inner(data, state, &mut inner)?;
                        operands.append(inner);
                    }
                    OperandHandleResolver::Symbol(symbol) => {
                        data.symbols[*symbol as usize].operands(data, state, operands);
                    }
                    OperandHandleResolver::Expression(expr) => {
                        expr.operands(data, state, operands);
                    }
                }
                state.input().pop_operand();
            }
        }
        Some(())
    }
}
