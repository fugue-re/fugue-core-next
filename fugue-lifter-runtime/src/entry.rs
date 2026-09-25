use std::fmt;

use crate::LiftingContextState;
use crate::format::{InstructionFormatError, InstructionFormatter};
use crate::language::LanguageData;
use crate::operand::{Operands, OperandsContext};
use crate::pcode::{LiftingContext, PCodeOp};

#[inline]
pub fn resolve(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    apply_commits: bool,
) -> Option<usize> {
    let data = context.language().data();
    unsafe {
        let mut nop_issued = Vec::with_capacity(0);
        let mut state = context.state_for(address, bytes, &mut nop_issued)?;

        let ctor = data.resolve_instruction(&mut state)?;

        let buffer_limit = bytes.len();
        let length = state.len();

        if length == 0 || length > buffer_limit {
            return None;
        }

        if apply_commits {
            ctor.resolve_handles(data, &mut state)?;
        }

        state.inputs.input.base_state();

        if apply_commits {
            state.apply_commits(data);
        }

        Some(length)
    }
}

#[inline]
pub fn operands(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    operand_context: &mut OperandsContext,
    operands: &mut Operands,
) -> Option<usize> {
    let language = context.language();
    let data = language.data();

    operands.clear();

    let length = unsafe {
        let mut nop_issued = Vec::with_capacity(0);
        let mut state = context.state_for(address, bytes, &mut nop_issued)?;

        let ctor = data.resolve_instruction(&mut state)?;

        let buffer_limit = bytes.len();
        let length = state.len();

        if length == 0 || length > buffer_limit {
            return None;
        }

        ctor.resolve_handles(data, &mut state)?;

        state.inputs.input.base_state();

        state.apply_commits(data);

        state.operands(language, operands)?;

        length
    };

    if lift(address, bytes, context, operand_context.operations_mut()).is_some() {
        operands.correlate(language, operand_context);
    }

    Some(length)
}

#[inline]
pub fn disassemble(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    output: &mut String,
) -> Option<usize> {
    disassemble_to(address, bytes, context, output).unwrap()
}

#[inline]
pub fn disassemble_and_format<F: InstructionFormatter + ?Sized>(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    formatter: &mut F,
) -> Result<Option<usize>, fmt::Error> {
    let language = context.language();
    disassemble_and_format_aux(address, bytes, context, |_data, state| unsafe {
        state.format_instruction(language, formatter)
    })
}

#[inline]
pub fn disassemble_parts(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    mnemonic: &mut String,
    operands: &mut String,
) -> Option<usize> {
    disassemble_parts_to(address, bytes, context, mnemonic, operands).unwrap()
}

#[inline]
pub fn disassemble_to(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    writer: impl fmt::Write,
) -> Result<Option<usize>, fmt::Error> {
    let language = context.language();
    disassemble_and_format_aux(address, bytes, context, |_data, state| unsafe {
        state.format(language, writer)
    })
}

#[inline]
pub fn disassemble_parts_to(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    mnemonic: impl fmt::Write,
    operands: impl fmt::Write,
) -> Result<Option<usize>, fmt::Error> {
    let language = context.language();
    disassemble_and_format_aux(address, bytes, context, |_data, state| unsafe {
        state.format_parts(language, mnemonic, operands)
    })
}

#[inline]
pub fn disassemble_aux<F>(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    formatter: F,
) -> Result<Option<usize>, fmt::Error>
where
    F: FnOnce(&'static LanguageData, &mut LiftingContextState<'_>) -> fmt::Result,
{
    disassemble_with(address, bytes, context, formatter)
}

fn disassemble_and_format_aux<F>(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    formatter: F,
) -> Result<Option<usize>, fmt::Error>
where
    F: FnOnce(
        &'static LanguageData,
        &mut LiftingContextState<'_>,
    ) -> Result<(), InstructionFormatError>,
{
    match disassemble_with(address, bytes, context, formatter) {
        Ok(length) => Ok(length),
        Err(InstructionFormatError::Formatting(error)) => Err(error),
        Err(InstructionFormatError::Unresolved) => Ok(None),
    }
}

fn disassemble_with<E, F>(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    formatter: F,
) -> Result<Option<usize>, E>
where
    F: FnOnce(&'static LanguageData, &mut LiftingContextState<'_>) -> Result<(), E>,
{
    let data = context.language().data();
    unsafe {
        let mut nop_issued = Vec::with_capacity(0);

        let Some(mut state) = context.state_for(address, bytes, &mut nop_issued) else {
            return Ok(None);
        };

        let Some(ctor) = data.resolve_instruction(&mut state) else {
            return Ok(None);
        };

        let buffer_limit = bytes.len();
        let length = state.len();

        if length == 0 || length > buffer_limit {
            return Ok(None);
        }

        if ctor.resolve_handles(data, &mut state).is_none() {
            return Ok(None);
        }

        state.inputs.input.base_state();

        state.apply_commits(data);

        formatter(data, &mut state)?;

        Ok(Some(length))
    }
}

#[inline]
pub fn lift(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    issued: &mut Vec<PCodeOp>,
) -> Option<usize> {
    let data = context.language().data();
    unsafe {
        let mut state = context.state_for(address, bytes, issued)?;
        let buffer_limit = bytes.len();

        data.resolve_state(&mut state)?;

        let length = state.len();

        if length == 0 || length > buffer_limit {
            return None;
        }

        let delay_slot_bytes = state.delay_slot_length();

        if delay_slot_bytes == 0 {
            state.emit(data)?;
            return Some(state.len());
        }

        let mut fall_offset = state.len();
        let mut delay_count = 0usize;
        let mut index = 0usize;

        loop {
            let address = address + fall_offset as u64;
            let bytes = bytes.get(fall_offset..)?;

            let mut dstate = state.nth_delay_slot(index)?;

            dstate.inputs.initialise(address, bytes);

            data.resolve_state(&mut dstate)?;

            if dstate.delay_slot_length() != 0 {
                return None;
            }

            let length = dstate.len();

            if length == 0 || length > (buffer_limit - fall_offset) {
                return None;
            }

            fall_offset += length;
            delay_count += length;

            if delay_count >= delay_slot_bytes {
                break;
            }

            index += 1;
        }

        state.emit(data)?;

        Some(fall_offset)
    }
}
