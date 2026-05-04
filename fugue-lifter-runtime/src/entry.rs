use crate::constructor::Constructor;
use crate::data::{LanguageData, SpaceKind};
use crate::operand::Operands;
use crate::pcode::{LiftingContext, LiftingContextState, PCodeOp};
use crate::{calculate_mask, wrap_offset};

#[inline(always)]
pub(crate) fn resolve_upper_bound(data: &'static LanguageData, space: u8) -> u64 {
    data.spaces[space as usize].upper_bound
}

#[inline(always)]
pub(crate) fn resolve_word_size(data: &'static LanguageData, space: u8) -> usize {
    data.spaces[space as usize].word_size
}

#[inline(always)]
pub(crate) fn resolve_location_offset(
    data: &'static LanguageData,
    unique_offset: u64,
    space: u8,
    offset: u64,
    size: u16,
) -> u64 {
    let info = &data.spaces[space as usize];
    match info.kind {
        SpaceKind::Constant => offset & calculate_mask(size as usize),
        SpaceKind::Unique => offset | unique_offset,
        SpaceKind::Default | SpaceKind::Other => wrap_offset(info.upper_bound, offset),
    }
}

#[inline(always)]
pub(crate) fn resolve_constructor(
    data: &'static LanguageData,
    id: u16,
    state: &mut LiftingContextState,
) -> Option<&'static Constructor> {
    data.decision_trees[id as usize].resolve(data, state)
}

#[inline(always)]
pub(crate) fn resolve_instruction(
    data: &'static LanguageData,
    state: &mut LiftingContextState,
) -> Option<&'static Constructor> {
    unsafe {
        let ctor = data.decision_trees[data.root_dtree as usize].resolve(data, state)?;
        ctor.resolve_operands(data, state)?;
        Some(ctor)
    }
}

#[inline(always)]
pub(crate) fn resolve_state(
    data: &'static LanguageData,
    state: &mut LiftingContextState,
) -> Option<&'static Constructor> {
    unsafe {
        let ctor = resolve_instruction(data, state)?;
        ctor.resolve_handles(data, state)?;
        state.inputs.input.base_state();
        state.apply_commits(data);
        Some(ctor)
    }
}

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

        let ctor = resolve_instruction(data, &mut state)?;

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
    operands: &mut Operands,
) -> Option<usize> {
    let data = context.language().data();
    unsafe {
        let mut nop_issued = Vec::with_capacity(0);
        let mut state = context.state_for(address, bytes, &mut nop_issued)?;

        let ctor = resolve_instruction(data, &mut state)?;

        let buffer_limit = bytes.len();
        let length = state.len();

        if length == 0 || length > buffer_limit {
            return None;
        }

        ctor.resolve_handles(data, &mut state)?;

        state.inputs.input.base_state();

        state.apply_commits(data);

        state.operands(data, operands)?;

        Some(length)
    }
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
pub fn disassemble_to<W: std::fmt::Write>(
    address: u64,
    bytes: &[u8],
    context: &mut LiftingContext,
    writer: &mut W,
) -> Result<Option<usize>, std::fmt::Error> {
    let data = context.language().data();
    unsafe {
        let mut nop_issued = Vec::with_capacity(0);

        let Some(mut state) = context.state_for(address, bytes, &mut nop_issued) else {
            return Ok(None);
        };

        let Some(ctor) = resolve_instruction(data, &mut state) else {
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

        state.format(data, writer)?;

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

        resolve_state(data, &mut state)?;

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

            resolve_state(data, &mut dstate)?;

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
