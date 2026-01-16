use std::fmt::{self, Debug};

use crate::context::{ContextPostAction, ContextPreAction};
use crate::input::{ContextCommit, FixedHandle, INVALID_HANDLE};
use crate::pattern::{PatternExpression, PatternOp};
use crate::pcode::LiftingContextState;
use crate::resolve::DecisionNode;
use crate::symbol::Symbol;
use crate::template::{handle_tpl, ConstTpl, ConstructTpl, HandleTpl, OpTpl, VarnodeTpl};

// pub type ContextActionSet = fn(&mut LiftingContextState<'_>) -> Option<()>;

pub enum OperandResolver {
    None,
    Constructor(u16),
    Filter(u16),
}

pub struct OperandFilter {
    pub pattern: PatternExpression,
    pub indices: &'static [u16],
    pub limit: u16,
}

impl OperandFilter {
    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn validate<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState,
    ) -> Option<()> {
        let index = u16::try_from(self.pattern.resolve::<R>(input)?).ok()?;
        if index >= self.limit || self.indices.contains(&index) {
            None
        } else {
            Some(())
        }
    }
}

pub enum OperandHandleResolver {
    None,
    Symbol(u16),
    Expression(PatternExpression),
}

pub struct Operand {
    pub resolver: OperandResolver,
    pub handle_resolver: OperandHandleResolver,
    pub offset_base: Option<usize>,
    pub offset_rela: usize,
    pub minimum_length: usize,
}

pub trait ConstructorResolver {
    const ADDRESS_SIZE: usize;
    const DEFAULT_SPACE: u8;
    const UNIQUE_SPACE: u8;

    const CONSTRUCTORS: &'static [Constructor];
    const DECISION_TREES: &'static [DecisionNode];
    const OPERAND_FILTERS: &'static [OperandFilter];
    const PATTERN_EXPRESSIONS: &'static [PatternOp];
    const SYMBOLS: &'static [Symbol];

    const CONST_TEMPLATES: &'static [ConstTpl];
    const CONSTRUCT_TEMPLATES: &'static [ConstructTpl];
    const HANDLE_TEMPLATES: &'static [HandleTpl];
    const OP_TEMPLATES: &'static [OpTpl];
    const VARNODE_TEMPLATES: &'static [VarnodeTpl];

    fn resolve(input: &mut LiftingContextState) -> Option<&'static Constructor>;
    fn resolve_constructor(
        id: u16,
        input: &mut LiftingContextState,
    ) -> Option<&'static Constructor>;
    fn resolve_upper_bound(space: u8) -> u64;
    fn resolve_word_size(space: u8) -> usize;
    fn resolve_location_offset(unique_offset: u64, space: u8, offset: u64, size: u16) -> u64;
}

pub type ConstructorResult = fn(&mut LiftingContextState<'_>) -> FixedHandle;

pub type PCodeBuildAction = fn(&mut LiftingContextState<'_>) -> Option<()>;

pub struct Constructor {
    pub id: u16,
    pub context_pre_actions: &'static [ContextPreAction],
    pub context_post_actions: &'static [ContextPostAction],
    pub operands: &'static [Operand],
    pub result: Option<u16>, // HandleTpl
    pub build_action: Option<u16>, // ConstructTpl
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

// print pieces:
// - Symbol(operand index)
// - Token

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
    pub unsafe fn apply_context_actions<R: ConstructorResolver>(
        &'static self,
        state: &mut LiftingContextState,
    ) -> Option<()> {
        for action in self.context_pre_actions {
            action.apply::<R>(state)?;
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
    pub unsafe fn resolve_operands<R: ConstructorResolver>(
        &'static self,
        state: &mut LiftingContextState,
    ) -> Option<()> {
        state.input().set_constructor(self);

        self.apply_context_actions::<R>(state)?;

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
                        R::OPERAND_FILTERS[filter as usize].validate::<R>(state)?;
                    }
                    OperandResolver::Constructor(id) => {
                        let ctor = R::resolve_constructor(id, state)?;

                        state.input().set_constructor(ctor);

                        ctor.apply_context_actions::<R>(state)?;

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
    pub unsafe fn resolve_handles<R: ConstructorResolver>(
        &'static self,
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
                        let handle = R::SYMBOLS[symbol as usize].resolve_handle::<R>(state)?;
                        state.input().set_parent_handle(handle);
                    }
                    OperandHandleResolver::Expression(ref expr) => {
                        let offset = expr.resolve::<R>(state)? as u64;

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
                let handle = handle_tpl::<R>(tmpl).build::<R>(state)?;
                state.input().set_parent_handle(handle);
            }

            state.input().pop_operand();
        }

        Some(())
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn format_mnemonic<R: ConstructorResolver, W: fmt::Write>(
        &self,
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
                    .format_mnemonic::<R, _>(state, writer)?;
                state.input().pop_operand();
                return Ok(());
            }
        }

        let Some(pieces) = self.print_pieces.get(
            ..self
                .first_whitespace
                .unwrap_or(self.print_pieces.len()),
        ) else {
            return Ok(());
        };

        for p in pieces {
            match p {
                PrintPiece::Operand(index) => match &self.operands[*index as usize].handle_resolver
                {
                    OperandHandleResolver::None => {
                        state.input().push_operand(*index as usize);
                        state.input().constructor().format::<R, _>(state, writer)?;
                        state.input().pop_operand();
                    }
                    OperandHandleResolver::Symbol(symbol) => {
                        R::SYMBOLS[*symbol as usize].format::<R, _>(state, writer)?;
                    }
                    OperandHandleResolver::Expression(expr) => {
                        expr.format::<R, _>(state, writer)?;
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
    pub unsafe fn format_body<R: ConstructorResolver, W: fmt::Write>(
        &self,
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
                    .format_body::<R, _>(state, writer)?;
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
                        state.input().constructor().format::<R, _>(state, writer)?;
                        state.input().pop_operand();
                    }
                    OperandHandleResolver::Symbol(symbol) => {
                        R::SYMBOLS[*symbol as usize].format::<R, _>(state, writer)?;
                    }
                    OperandHandleResolver::Expression(expr) => {
                        expr.format::<R, _>(state, writer)?;
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
    pub unsafe fn format<R: ConstructorResolver, W: fmt::Write>(
        &self,
        state: &mut LiftingContextState<'_>,
        writer: &mut W,
    ) -> Result<(), fmt::Error> {
        for p in self.print_pieces {
            match p {
                PrintPiece::Operand(index) => {
                    state.input().push_operand(*index as usize);
                    match &self.operands[*index as usize].handle_resolver {
                        OperandHandleResolver::None => {
                            state.input().constructor().format::<R, _>(state, writer)?;
                        }
                        OperandHandleResolver::Symbol(symbol) => {
                            R::SYMBOLS[*symbol as usize].format::<R, _>(state, writer)?;
                        }
                        OperandHandleResolver::Expression(expr) => {
                            expr.format::<R, _>(state, writer)?;
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
}
