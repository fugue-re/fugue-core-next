use std::fmt;

use crate::input::FixedHandle;
use crate::language::{Language, LanguageData};
use crate::operand::{OperandPiece, Operands};
use crate::pattern::PatternExpression;
use crate::pcode::LiftingContextState;

#[derive(Debug)]
pub enum Symbol {
    Epsilon,
    Value {
        pattern_value: PatternExpression,
    },
    ValueMap {
        pattern_value: PatternExpression,
        value_table: &'static [Option<i64>],
    },
    ValueMapFilled {
        pattern_value: PatternExpression,
        value_table: &'static [i64],
    },
    Name {
        pattern_value: PatternExpression,
        symbol_table: &'static [Option<&'static str>],
    },
    Varnode {
        name: &'static str,
        space: u8,
        offset: u64,
        size: u16,
    },
    VarnodeList {
        pattern_value: PatternExpression,
        varnode_table: &'static [Option<u16>],
        symbol_table: &'static [Option<&'static str>],
    },
    VarnodeListFilled {
        pattern_value: PatternExpression,
        varnode_table: &'static [u16],
        symbol_table: &'static [&'static str],
    },
    Operand {
        handle_index: usize,
    },
    Start {
        space: u8,
        size: u16,
    },
    End {
        space: u8,
        size: u16,
    },
    Next2 {
        space: u8,
        size: u16,
    },
}

impl Symbol {
    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn format<W: fmt::Write>(
        &self,
        data: &'static LanguageData,
        state: &mut LiftingContextState<'_>,
        writer: &mut W,
    ) -> fmt::Result {
        unsafe {
            match self {
                Self::Varnode { name, .. } => {
                    writer.write_str(name)?;
                }
                Self::Name {
                    pattern_value,
                    symbol_table,
                }
                | Self::VarnodeList {
                    pattern_value,
                    symbol_table,
                    ..
                } => {
                    let index = pattern_value.resolve(data, state).expect("resolved");
                    if let Some(name) = symbol_table.get(index as usize).copied().flatten() {
                        writer.write_str(name)?;
                    }
                }
                Self::VarnodeListFilled {
                    pattern_value,
                    symbol_table,
                    ..
                } => {
                    let index = pattern_value.resolve(data, state).expect("resolved");
                    if let Some(name) = symbol_table.get(index as usize).copied() {
                        writer.write_str(name)?;
                    }
                }
                Self::ValueMap {
                    pattern_value,
                    value_table,
                } => {
                    let index = pattern_value.resolve(data, state).expect("resolved");
                    if let Some(value) = value_table.get(index as usize).copied().flatten() {
                        if value < 0 {
                            write!(writer, "-{:#x}", -(value as i128))?;
                        } else {
                            write!(writer, "{:#x}", value)?;
                        }
                    }
                }
                Self::ValueMapFilled {
                    pattern_value,
                    value_table,
                } => {
                    let index = pattern_value.resolve(data, state).expect("resolved");
                    let value = *value_table.get(index as usize).expect("resolved");
                    if value < 0 {
                        write!(writer, "-{:#x}", -(value as i128))?;
                    } else {
                        write!(writer, "{:#x}", value)?;
                    }
                }
                Self::Start { .. } => {
                    write!(writer, "{:#x}", state.address())?;
                }
                Self::End { .. } => {
                    write!(writer, "{:#x}", state.next_address())?;
                }
                Self::Next2 { .. } => {
                    write!(writer, "{:#x}", state.next2_address().expect("resolved"))?;
                }
                what => unreachable!("this state should not be reachable: {what:?}"),
            }
            Ok(())
        }
    }

    pub(crate) unsafe fn operand_pieces(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        operands: &mut Operands,
    ) -> Option<()> {
        unsafe {
            let data = language.data();
            match self {
                Self::Varnode {
                    name,
                    space,
                    offset,
                    size,
                } => {
                    operands.push_piece(OperandPiece::from_varnode(
                        language, name, *space, *offset, *size,
                    ));
                }
                Self::Name {
                    pattern_value,
                    symbol_table,
                } => {
                    let (index, resolved) = pattern_value.resolve_with_range(data, state)?;
                    if let Some(name) = symbol_table.get(index as usize).copied().flatten() {
                        operands.push_piece(OperandPiece::Text(name));
                        operands.merge_bits(resolved);
                    }
                }
                Self::VarnodeList {
                    pattern_value,
                    symbol_table,
                    ..
                } => {
                    let (index, resolved) = pattern_value.resolve_with_range(data, state)?;
                    if let Some(name) = symbol_table.get(index as usize).copied().flatten() {
                        operands.push_piece(OperandPiece::register(language, name));
                        operands.merge_bits(resolved);
                    }
                }
                Self::VarnodeListFilled {
                    pattern_value,
                    symbol_table,
                    ..
                } => {
                    let (index, resolved) = pattern_value.resolve_with_range(data, state)?;
                    if let Some(name) = symbol_table.get(index as usize).copied() {
                        operands.push_piece(OperandPiece::register(language, name));
                        operands.merge_bits(resolved);
                    }
                }
                Self::ValueMap {
                    pattern_value,
                    value_table,
                } => {
                    let (index, resolved) = pattern_value.resolve_with_range(data, state)?;
                    if let Some(value) = value_table.get(index as usize).copied().flatten() {
                        let signed = pattern_value.has_signed_terms(data);
                        operands.push_piece(OperandPiece::scalar(value, resolved.as_ref(), signed));
                        operands.merge_bits(resolved);
                    }
                }
                Self::ValueMapFilled {
                    pattern_value,
                    value_table,
                } => {
                    let (index, resolved) = pattern_value.resolve_with_range(data, state)?;
                    let value = value_table.get(index as usize).copied()?;
                    let signed = pattern_value.has_signed_terms(data);
                    operands.push_piece(OperandPiece::scalar(value, resolved.as_ref(), signed));
                    operands.merge_bits(resolved);
                }
                Self::Start { .. } => {
                    operands.push_piece(OperandPiece::Address(state.address()));
                }
                Self::End { .. } => {
                    operands.push_piece(OperandPiece::Address(state.next_address()));
                }
                Self::Next2 { .. } => {
                    operands.push_piece(OperandPiece::Address(state.next2_address()?));
                }
                what => unreachable!("this state should not be reachable: {what:?}"),
            }
            Some(())
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn resolve_handle(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<FixedHandle> {
        unsafe {
            Some(match self {
                Symbol::Epsilon => FixedHandle {
                    space: 0,
                    ..Default::default()
                },
                Symbol::Name { pattern_value, .. } | Symbol::Value { pattern_value } => {
                    let value = pattern_value.resolve(data, input)?;
                    FixedHandle {
                        space: 0,
                        offset_offset: value as u64,
                        ..Default::default()
                    }
                }
                Symbol::Varnode {
                    space,
                    offset,
                    size,
                    ..
                } => FixedHandle {
                    space: *space,
                    size: *size,
                    offset_offset: *offset,
                    ..Default::default()
                },
                Symbol::Operand { handle_index } => {
                    input.input().unchecked_operand_handle(*handle_index)
                }
                Symbol::Start { space, size } => FixedHandle {
                    space: *space,
                    size: *size,
                    offset_offset: input.address(),
                    ..Default::default()
                },
                Symbol::End { space, size } => FixedHandle {
                    space: *space,
                    size: *size,
                    offset_offset: input.next_address(),
                    ..Default::default()
                },
                Symbol::Next2 { space, size } => FixedHandle {
                    space: *space,
                    size: *size,
                    offset_offset: if let Some(next2_address) = input.next2_address() {
                        next2_address
                    } else {
                        let mut ninput = input.next_input()?;
                        data.resolve_instruction(&mut ninput)?;
                        ninput.next_address()
                    },
                    ..Default::default()
                },
                Symbol::VarnodeList {
                    pattern_value,
                    varnode_table,
                    ..
                } => {
                    let index = pattern_value.resolve(data, input)? as usize;
                    let symbol = &data.symbols[varnode_table.get(index).copied()?? as usize];
                    symbol.resolve_handle(data, input)?
                }
                Symbol::VarnodeListFilled {
                    pattern_value,
                    varnode_table,
                    ..
                } => {
                    let index = pattern_value.resolve(data, input)? as usize;
                    let symbol = &data.symbols[*varnode_table.get(index)? as usize];
                    symbol.resolve_handle(data, input)?
                }
                Symbol::ValueMap {
                    pattern_value,
                    value_table,
                } => {
                    let index = pattern_value.resolve(data, input)? as usize;
                    let value = *value_table.get(index)?.as_ref()? as u64;

                    FixedHandle {
                        space: 0,
                        offset_offset: value,
                        ..Default::default()
                    }
                }
                Symbol::ValueMapFilled {
                    pattern_value,
                    value_table,
                } => {
                    let index = pattern_value.resolve(data, input)? as usize;
                    let value = *value_table.get(index)? as u64;

                    FixedHandle {
                        space: 0,
                        offset_offset: value,
                        ..Default::default()
                    }
                }
            })
        }
    }
}
