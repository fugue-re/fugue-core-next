use std::fmt;
use std::ops::Range;

use crate::format::{InstructionFormatError, InstructionSection, InstructionWriter};
use crate::input::{BREADCRUMBS, INVALID_HANDLE};
use crate::language::{Language, LanguageData};
use crate::operand::OperandPiece;
use crate::pcode::LiftingContextState;
use crate::{byte_swap, sign_extend, zero_extend};

#[derive(Debug, Copy, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum OperandOffset {
    Relative(u8),
    Operand(u8),
}

#[derive(Debug, Copy, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PatternExpression(u16, u16);

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum PatternOp {
    TokenField {
        big_endian: bool,
        sign_bit: bool,
        bit_start: u8,
        bit_end: u8,
        byte_start: u8,
        byte_end: u8,
        shift: u8,
    },
    ContextField {
        sign_bit: bool,
        bit_start: u8,
        bit_end: u8,
        byte_start: u8,
        byte_end: u8,
        shift: u8,
    },
    Constant {
        value: i64,
    },
    Operand {
        constructor: u16,
        offset: OperandOffset,
        value: PatternExpression,
    },
    StartInstruction,
    EndInstruction,
    Next2Instruction,
    Plus,
    Sub,
    Mult,
    LeftShift,
    RightShift,
    And,
    Or,
    Xor,
    Div,
    Minus,
    Not,
}

impl PatternExpression {
    pub const fn new(start: u16, end: u16) -> Self {
        Self(start, end)
    }

    #[inline(always)]
    fn range(&self) -> Range<usize> {
        let start = self.0 as usize;
        let end = self.1 as usize;
        start..end
    }

    #[inline(always)]
    fn operations(&self, data: &'static LanguageData) -> &'static [PatternOp] {
        &data.pattern_expressions[self.range()]
    }

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
            let value = self
                .resolve(data, state)
                .expect("value previously resolved");
            if value < 0 && self.has_signed_terms(data) {
                write!(writer, "-{:#x}", -(value as i128))
            } else {
                write!(writer, "{:#x}", value as u64)
            }
        }
    }

    pub(crate) fn has_signed_terms(&self, data: &'static LanguageData) -> bool {
        self.operations(data).iter().any(|op| match op {
            PatternOp::TokenField { sign_bit, .. } | PatternOp::ContextField { sign_bit, .. } => {
                *sign_bit
            }
            PatternOp::Constant { value } => *value < 0,
            PatternOp::Sub | PatternOp::Minus | PatternOp::Not => true,
            PatternOp::Operand { value, .. } => value.has_signed_terms(data),
            _ => false,
        })
    }

    pub(crate) unsafe fn operand_pieces<O: InstructionWriter + ?Sized>(
        &self,
        language: &'static Language,
        state: &mut LiftingContextState<'_>,
        output: &mut O,
        section: InstructionSection,
    ) -> Result<(), InstructionFormatError> {
        unsafe {
            let data = language.data();
            let (value, resolved) = self
                .resolve_with_range(data, state)
                .ok_or(InstructionFormatError::Unresolved)?;
            let signed = self.has_signed_terms(data);
            section.write(
                output,
                OperandPiece::scalar(value, resolved.as_ref(), signed),
                resolved,
            )?;
            Ok(())
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn resolve(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<i64> {
        unsafe { self.resolve_with_range(data, input).map(|(value, _)| value) }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline(always)]
    pub(crate) unsafe fn resolve_with_range(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<(i64, Option<Range<u32>>)> {
        unsafe {
            let mut stack = Vec::new();
            let operations = self.operations(data);

            let mut range = None;
            let update_range = |c: &mut Option<Range<u32>>, new: Range<u32>| {
                *c = Some(match c {
                    Some(old) => old.start.min(new.start)..old.end.max(new.end),
                    None => new,
                })
            };
            let field_range = |input: &LiftingContextState<'_>,
                               byte_start: u8,
                               bit_start: u8,
                               bit_end: u8,
                               size: isize| {
                let soff = 8u32 * ((byte_start as u32) + input.inputs.input.offset() as u32);
                let eoff = 8u32 * (size as u32);
                let loff = soff + eoff;
                let soff_bits = loff - (bit_end as u32 + 1);
                let eoff_bits = loff - (bit_start as u32);
                soff_bits..eoff_bits
            };

            'outer: for op in operations {
                match op {
                    PatternOp::TokenField {
                        big_endian,
                        sign_bit,
                        bit_start,
                        bit_end,
                        byte_start,
                        byte_end,
                        shift,
                    } => {
                        let size = usize::from(byte_end - byte_start + 1);
                        let shift = u32::from(*shift);

                        let mut res = 0i64;
                        let mut start = *byte_start as isize;
                        let mut tsize = size as isize;

                        while tsize >= size_of::<u32>() as isize {
                            let tmp = input
                                .input()
                                .instruction_bytes(start as usize, size_of::<u32>())?;
                            res = res.checked_shl(8 * size_of::<u32>() as u32).unwrap_or(0);
                            res = (res as u64 | tmp as u64) as i64;
                            start += size_of::<u32>() as isize;
                            tsize = (*byte_end as isize) - start + 1;
                        }
                        if tsize > 0 {
                            let tmp = input
                                .input()
                                .instruction_bytes(start as usize, tsize as usize)?;
                            res = res.checked_shl(8 * tsize as u32).unwrap_or(0);
                            res = (res as u64 | tmp as u64) as i64;
                        }

                        res = if !big_endian {
                            byte_swap(res, size)
                        } else {
                            res
                        };
                        res = res
                            .checked_shr(shift)
                            .unwrap_or(if res < 0 { -1 } else { 0 });

                        update_range(
                            &mut range,
                            field_range(input, *byte_start, *bit_start, *bit_end, size as _),
                        );

                        stack.push(if *sign_bit {
                            sign_extend(res, usize::from(bit_end - bit_start))
                        } else {
                            zero_extend(res, usize::from(bit_end - bit_start))
                        });
                    }
                    PatternOp::ContextField {
                        sign_bit,
                        bit_start,
                        bit_end,
                        byte_start,
                        byte_end,
                        shift,
                    } => {
                        let shift = u32::from(*shift);

                        let mut res = 0i64;
                        let mut size = (*byte_end as isize) - (*byte_start as isize) + 1;
                        let mut start = *byte_start as isize;

                        while size >= size_of::<u32>() as isize {
                            let tmp = input
                                .input()
                                .context_bytes(start as usize, size_of::<u32>());
                            res = res.checked_shl(8 * size_of::<u32>() as u32).unwrap_or(0);
                            res = (res as u64 | tmp as u64) as i64;
                            start += size_of::<u32>() as isize;
                            size = (*byte_end as isize) - start + 1;
                        }
                        if size > 0 {
                            let tmp = input.input().context_bytes(start as usize, size as usize);
                            res = res.checked_shl(8 * size as u32).unwrap_or(0);
                            res = (res as u64 | tmp as u64) as i64;
                        }

                        res = res
                            .checked_shr(shift)
                            .unwrap_or(if res < 0 { -1 } else { 0 });

                        update_range(
                            &mut range,
                            field_range(input, *byte_start, *bit_start, *bit_end, size),
                        );

                        stack.push(if *sign_bit {
                            sign_extend(res, usize::from(bit_end - bit_start))
                        } else {
                            zero_extend(res, usize::from(bit_end - bit_start))
                        });
                    }
                    PatternOp::Constant { value } => stack.push(*value),
                    PatternOp::Operand {
                        constructor,
                        offset,
                        value,
                    } => {
                        let mut cur_depth = input.inputs.input.depth;
                        let mut point = &input.inputs.input.context.constructors
                            [input.inputs.input.point as usize];

                        let ctor = &data.constructors[*constructor as usize];
                        let ctor_id = ctor.id;

                        while point.constructor.map(|ctor| ctor.id) != Some(ctor_id) {
                            if cur_depth <= 0 {
                                let old_point = input.inputs.input.point;
                                let old_depth = std::mem::take(&mut input.inputs.input.depth);
                                let old_breadcrumb = std::mem::replace(
                                    &mut input.inputs.input.breadcrumb,
                                    [0u8; BREADCRUMBS],
                                );

                                input.inputs.input.point = input.inputs.input.context.alloc;
                                {
                                    let cstate = &mut input.inputs.input.context.constructors
                                        [input.inputs.input.point as usize];

                                    cstate.constructor = Some(ctor);
                                    cstate.handle = None;
                                    cstate.parent = INVALID_HANDLE;
                                    cstate.operands = INVALID_HANDLE;
                                    cstate.offset = 0;
                                    cstate.length = 0;
                                }

                                let (value, nrange) = value.resolve_with_range(data, input)?;

                                if let Some(nrange) = nrange {
                                    update_range(&mut range, nrange);
                                }

                                {
                                    let cstate = &mut input.inputs.input.context.constructors
                                        [input.inputs.input.point as usize];

                                    cstate.constructor = None;
                                    cstate.handle = None;
                                    cstate.parent = INVALID_HANDLE;
                                    cstate.operands = INVALID_HANDLE;
                                    cstate.offset = 0;
                                    cstate.length = 0;
                                }

                                input.inputs.input.point = old_point;
                                input.inputs.input.depth = old_depth;
                                input.inputs.input.breadcrumb = old_breadcrumb;

                                stack.push(value);
                                continue 'outer;
                            }

                            cur_depth -= 1;
                            point = &input.inputs.input.context.constructors[point.parent as usize];
                        }

                        let offset = match offset {
                            OperandOffset::Relative(offset) => point.offset + *offset,
                            OperandOffset::Operand(index) => {
                                input.inputs.input.context.constructors
                                    [point.operands as usize + *index as usize]
                                    .offset
                            }
                        };
                        let length = point.length;

                        let old_point = input.inputs.input.point;
                        let old_depth = std::mem::take(&mut input.inputs.input.depth);
                        let old_breadcrumb = std::mem::replace(
                            &mut input.inputs.input.breadcrumb,
                            [0u8; BREADCRUMBS],
                        );

                        input.inputs.input.point = input.inputs.input.context.alloc;
                        {
                            let cstate = &mut input.inputs.input.context.constructors
                                [input.inputs.input.point as usize];

                            cstate.constructor = Some(ctor);
                            cstate.handle = None;
                            cstate.parent = INVALID_HANDLE;
                            cstate.operands = INVALID_HANDLE;
                            cstate.offset = offset;
                            cstate.length = length;
                        }

                        let (value, nrange) = value.resolve_with_range(data, input)?;

                        if let Some(nrange) = nrange {
                            update_range(&mut range, nrange);
                        }

                        {
                            let cstate = &mut input.inputs.input.context.constructors
                                [input.inputs.input.point as usize];

                            cstate.constructor = None;
                            cstate.handle = None;
                            cstate.parent = INVALID_HANDLE;
                            cstate.operands = INVALID_HANDLE;
                            cstate.offset = 0;
                            cstate.length = 0;
                        }

                        input.inputs.input.point = old_point;
                        input.inputs.input.depth = old_depth;
                        input.inputs.input.breadcrumb = old_breadcrumb;

                        stack.push(value);
                    }
                    PatternOp::StartInstruction => stack.push(input.address() as i64),
                    PatternOp::EndInstruction => stack.push(input.next_address() as i64),
                    PatternOp::Next2Instruction => {
                        let value = input.next2_address().map_or_else(
                            || {
                                let mut ninput = input.next_input()?;
                                data.resolve_instruction(&mut ninput)?;
                                Some(ninput.next_address() as i64)
                            },
                            |v| Some(v as i64),
                        )?;
                        stack.push(value);
                    }
                    PatternOp::And => {
                        let rhs = stack.pop()?;
                        let lhs = stack.pop()?;
                        stack.push(lhs & rhs);
                    }
                    PatternOp::Or => {
                        let rhs = stack.pop()?;
                        let lhs = stack.pop()?;
                        stack.push(lhs | rhs);
                    }
                    PatternOp::Xor => {
                        let rhs = stack.pop()?;
                        let lhs = stack.pop()?;
                        stack.push(lhs ^ rhs);
                    }
                    PatternOp::Plus => {
                        let rhs = stack.pop()?;
                        let lhs = stack.pop()?;
                        stack.push(lhs.wrapping_add(rhs));
                    }
                    PatternOp::Sub => {
                        let rhs = stack.pop()?;
                        let lhs = stack.pop()?;
                        stack.push(lhs.wrapping_sub(rhs));
                    }
                    PatternOp::Div => {
                        let rhs = stack.pop()?;
                        let lhs = stack.pop()?;
                        (rhs != 0).then(|| stack.push(lhs.wrapping_div(rhs)))?;
                    }
                    PatternOp::Mult => {
                        let rhs = stack.pop()?;
                        let lhs = stack.pop()?;
                        stack.push(lhs.wrapping_mul(rhs));
                    }
                    PatternOp::LeftShift => {
                        let rhs = stack.pop()?;
                        let lhs = stack.pop()?;
                        stack.push(lhs.checked_shl(rhs as u8 as u32).unwrap_or(0));
                    }
                    PatternOp::RightShift => {
                        let rhs = stack.pop()?;
                        let lhs = stack.pop()?;
                        stack.push(lhs.checked_shr(rhs as u8 as u32).unwrap_or(if lhs < 0 {
                            -1
                        } else {
                            0
                        }));
                    }
                    PatternOp::Not => {
                        let rhs = stack.pop()?;
                        stack.push(!rhs);
                    }
                    PatternOp::Minus => {
                        let rhs = stack.pop()?;
                        stack.push(-rhs);
                    }
                }
            }

            stack.pop().map(|value| (value, range))
        }
    }
}
