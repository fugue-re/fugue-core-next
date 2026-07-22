use crate::input::{FixedHandle, INVALID_HANDLE};
use crate::language::LanguageData;
use crate::{LiftingContextState, pcode, wrap_offset};

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[repr(u16)]
pub enum Op {
    Copy,
    Load,
    Store,
    Branch,
    CBranch,
    IBranch,
    Call,
    ICall,
    CallOther,
    Return,
    IntEq,
    IntNotEq,
    IntSLess,
    IntSLessEq,
    IntLess,
    IntLessEq,
    IntZExt,
    IntSExt,
    IntNeg,
    IntNot,
    IntAdd,
    IntSub,
    IntMul,
    IntDiv,
    IntSDiv,
    IntRem,
    IntSRem,
    IntCarry,
    IntSCarry,
    IntSBorrow,
    IntAnd,
    IntOr,
    IntXor,
    IntLShift,
    IntRShift,
    IntSRShift,
    BoolNot,
    BoolAnd,
    BoolOr,
    BoolXor,
    FloatEq,
    FloatNotEq,
    FloatLess,
    FloatLessEq,
    FloatIsNaN,
    FloatAdd,
    FloatSub,
    FloatMul,
    FloatDiv,
    FloatNeg,
    FloatAbs,
    FloatSqrt,
    FloatOfInt,
    FloatOfFloat,
    FloatTruncate,
    FloatCeiling,
    FloatFloor,
    FloatRound,
    Build,
    DelaySlot,
    Piece,
    Subpiece,
    Cast,
    Label,
    CrossBuild,
    SegmentOp,
    CPoolRef,
    New,
    Insert,
    Extract,
    PopCount,
    LZCount,
}

#[derive(Debug)]
pub struct ConstructTpl {
    pub delay_slot: u8,
    pub labels: u8,
    pub result: Option<u16>,
    pub operations: &'static [u16],
}

#[inline(always)]
pub(crate) fn construct_tpl(data: &'static LanguageData, idx: u16) -> &'static ConstructTpl {
    &data.construct_templates[idx as usize]
}

impl ConstructTpl {
    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn build(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<()> {
        unsafe {
            let old_base = input.context.label_base;

            input.context.label_base = input.context.label_count;
            input.context.label_count += self.labels;

            for &operation in self.operations {
                op_tpl(data, operation).build(data, input)?;
            }

            input.context.label_base = old_base;

            Some(())
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn build_result(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<FixedHandle> {
        unsafe {
            self.result
                .and_then(|handle| handle_tpl(data, handle).build(data, input))
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum HandleKind {
    Space,
    Offset,
    Size,
    OffsetPlus(u64),
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum ConstTpl {
    Real(u64),
    Handle(usize, HandleKind),
    Start,
    Next,
    Next2,
    CurrentSpace,
    CurrentSpaceSize,
    SpaceId(u8),
    Relative(u64),
}

#[inline(always)]
fn const_tpl(data: &'static LanguageData, idx: u16) -> &'static ConstTpl {
    &data.const_templates[idx as usize]
}

impl ConstTpl {
    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn update_offset(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
        handle: &mut FixedHandle,
    ) -> Option<()> {
        unsafe {
            match self {
                Self::Handle(index, _) => {
                    let h = input.operand_handle_mut(*index);

                    handle.offset_space = h.offset_space;
                    handle.offset_offset = h.offset_offset;
                    handle.offset_size = h.offset_size;
                    handle.temporary_space = h.temporary_space;
                    handle.temporary_offset = h.temporary_offset;
                }
                _ => {
                    let value = self.value(data, input)?;

                    handle.offset_space = INVALID_HANDLE;
                    handle.offset_offset = wrap_offset(data.space_upper_bound(handle.space), value);
                }
            }
            Some(())
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn space_via(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> u8 {
        unsafe {
            match self {
                Self::CurrentSpace => data.default_space,
                Self::Handle(index, HandleKind::Space) => {
                    let handle = input.input().operand_handle(*index);
                    if handle.offset_space == INVALID_HANDLE {
                        handle.space
                    } else {
                        handle.temporary_space
                    }
                }
                Self::SpaceId(id) => *id,
                _ => unreachable!("state should be unreachable via generated code"),
            }
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn space(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> u8 {
        unsafe {
            match self {
                Self::CurrentSpace => data.default_space,
                Self::Handle(index, HandleKind::Space) => {
                    let handle = input.input().operand_handle(*index);
                    handle.space
                }
                Self::SpaceId(id) => *id,
                _ => unreachable!("state should be unreachable via generated code"),
            }
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn value(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<u64> {
        unsafe {
            let value = match self {
                ConstTpl::Start => input.address(),
                ConstTpl::Next => input.next_address(),
                ConstTpl::Next2 => {
                    if let Some(next2_address) = input.next2_address() {
                        next2_address
                    } else {
                        let mut ninput = input.next_input()?;
                        data.resolve_instruction(&mut ninput)?;
                        ninput.next_address()
                    }
                }
                ConstTpl::CurrentSpaceSize => data.address_size as u64,
                ConstTpl::CurrentSpace => data.default_space as u64,
                ConstTpl::Relative(value) | ConstTpl::Real(value) => *value,
                ConstTpl::SpaceId(space) => *space as u64,
                ConstTpl::Handle(index, kind) => {
                    let handle = input.input().operand_handle(*index);
                    match kind {
                        HandleKind::Space => {
                            if handle.offset_space == INVALID_HANDLE {
                                handle.space as u64
                            } else {
                                handle.temporary_space as u64
                            }
                        }
                        HandleKind::Offset => {
                            if handle.offset_space == INVALID_HANDLE {
                                handle.offset_offset
                            } else {
                                handle.temporary_offset
                            }
                        }
                        HandleKind::Size => handle.size as u64,
                        HandleKind::OffsetPlus(value) => {
                            let value = *value;
                            let value_short = value & 0xffff;
                            let value_shift = 8 * (value >> 16) as u32;

                            if handle.space == 0 {
                                let val = if handle.offset_space == INVALID_HANDLE {
                                    handle.offset_offset
                                } else {
                                    handle.temporary_offset
                                };
                                val.checked_shr(value_shift).unwrap_or(0)
                            } else if handle.offset_space == INVALID_HANDLE {
                                handle.offset_offset + value_short
                            } else {
                                handle.temporary_offset + value_short
                            }
                        }
                    }
                }
            };
            Some(value)
        }
    }

    pub fn real(&self) -> u64 {
        match self {
            Self::Real(value) => *value,
            _ => 0,
        }
    }

    pub fn is_real(&self) -> bool {
        matches!(self, Self::Real(_))
    }

    pub fn handle_index(&self) -> Option<usize> {
        if let Self::Handle(index, _) = self {
            Some(*index)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct OpTpl {
    pub op: Op,
    pub inputs: &'static [u16],
    pub output: Option<u16>,
}

#[inline(always)]
fn op_tpl(data: &'static LanguageData, idx: u16) -> &'static OpTpl {
    &data.op_templates[idx as usize]
}

impl OpTpl {
    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn build(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState,
    ) -> Option<()> {
        unsafe {
            match self.op {
                Op::Build => self.append_build_action(data, input),
                Op::DelaySlot => self.delay_slot_action(data, input),
                Op::Label => {
                    let offset = varnode_tpl_offset(data, self.inputs[0]).real() as usize;
                    *input
                        .context
                        .labels
                        .get_unchecked_mut(offset + input.context.label_base as usize) =
                        input.issued.len() as i16;
                    Some(())
                }
                Op::CrossBuild => {
                    unimplemented!("cross-build is not supported")
                }
                _ => self.dump_action(data, input),
            }
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn append_build_action(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState,
    ) -> Option<()> {
        unsafe {
            let index = varnode_tpl_offset(data, self.inputs[0]).real() as usize;
            if let Some(operand) = input.operand_constructor(index) {
                input.input().push_operand(index);

                if let Some(builder) = operand.build_action {
                    construct_tpl(data, builder).build(data, input)?;
                }

                input.input().pop_operand();
            }
            Some(())
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn delay_slot_action(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState,
    ) -> Option<()> {
        unsafe { input.emit_delay_slots(data) }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn dump_action(
        &self,
        data: &'static LanguageData,
        state: &mut LiftingContextState,
    ) -> Option<()> {
        unsafe {
            let (index, op) = self.build_op(data, state)?;

            for &input in &self.inputs[index..] {
                varnode_tpl(data, input).build_input(data, state)?;
            }

            if self.inputs.first().is_some_and(|&input| {
                matches!(varnode_tpl_offset(data, input), ConstTpl::Relative(_))
            }) {
                state.context.inputs.0[0].offset += state.context.label_base as u64;
                state.context.label_refs.push(pcode::RelativeRecord {
                    operation: state.issued.len() as u8,
                    index: 0,
                });
            }

            let Some(output) = self.output.map(|idx| varnode_tpl(data, idx)) else {
                state.issue(op, pcode::Varnode::INVALID);
                return Some(());
            };

            output.build_output(data, state, op)
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    unsafe fn build_op(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<(usize, pcode::Op)> {
        unsafe {
            let (index, op) = match self.op {
                Op::Load => {
                    let space = varnode_tpl_offset_value(data, self.inputs[0], input)? as u8;
                    (1, pcode::Op::Load(space))
                }
                Op::Store => {
                    let space = varnode_tpl_offset_value(data, self.inputs[0], input)? as u8;
                    (1, pcode::Op::Store(space))
                }
                Op::CallOther => {
                    let index = varnode_tpl_offset_value(data, self.inputs[0], input)? as u16;
                    let count = self.inputs.len() as u8 - 1;
                    (1, pcode::Op::UserOp(index, count))
                }
                Op::Copy => (0, pcode::Op::Copy),
                Op::Branch => (0, pcode::Op::Branch),
                Op::CBranch => (0, pcode::Op::CBranch),
                Op::IBranch => (0, pcode::Op::IBranch),
                Op::Call => (0, pcode::Op::Call),
                Op::ICall => (0, pcode::Op::ICall),
                Op::Return => (0, pcode::Op::Return),
                Op::IntEq => (0, pcode::Op::IntEq),
                Op::IntNotEq => (0, pcode::Op::IntNotEq),
                Op::IntSLess => (0, pcode::Op::IntSignedLess),
                Op::IntSLessEq => (0, pcode::Op::IntSignedLessEq),
                Op::IntLess => (0, pcode::Op::IntLess),
                Op::IntLessEq => (0, pcode::Op::IntLessEq),
                Op::IntZExt => (0, pcode::Op::ZeroExt),
                Op::IntSExt => (0, pcode::Op::SignExt),
                Op::IntNeg => (0, pcode::Op::IntNeg),
                Op::IntNot => (0, pcode::Op::IntNot),
                Op::IntAdd => (0, pcode::Op::IntAdd),
                Op::IntSub => (0, pcode::Op::IntSub),
                Op::IntMul => (0, pcode::Op::IntMul),
                Op::IntDiv => (0, pcode::Op::IntDiv),
                Op::IntSDiv => (0, pcode::Op::IntSignedDiv),
                Op::IntRem => (0, pcode::Op::IntRem),
                Op::IntSRem => (0, pcode::Op::IntSignedRem),
                Op::IntCarry => (0, pcode::Op::IntCarry),
                Op::IntSCarry => (0, pcode::Op::IntSignedCarry),
                Op::IntSBorrow => (0, pcode::Op::IntSignedBorrow),
                Op::IntAnd => (0, pcode::Op::IntAnd),
                Op::IntOr => (0, pcode::Op::IntOr),
                Op::IntXor => (0, pcode::Op::IntXor),
                Op::IntLShift => (0, pcode::Op::IntLeftShift),
                Op::IntRShift => (0, pcode::Op::IntRightShift),
                Op::IntSRShift => (0, pcode::Op::IntSignedRightShift),
                Op::BoolNot => (0, pcode::Op::BoolNot),
                Op::BoolAnd => (0, pcode::Op::BoolAnd),
                Op::BoolOr => (0, pcode::Op::BoolOr),
                Op::BoolXor => (0, pcode::Op::BoolXor),
                Op::FloatEq => (0, pcode::Op::FloatEq),
                Op::FloatNotEq => (0, pcode::Op::FloatNotEq),
                Op::FloatLess => (0, pcode::Op::FloatLess),
                Op::FloatLessEq => (0, pcode::Op::FloatLessEq),
                Op::FloatIsNaN => (0, pcode::Op::FloatIsNaN),
                Op::FloatAdd => (0, pcode::Op::FloatAdd),
                Op::FloatSub => (0, pcode::Op::FloatSub),
                Op::FloatMul => (0, pcode::Op::FloatMul),
                Op::FloatDiv => (0, pcode::Op::FloatDiv),
                Op::FloatNeg => (0, pcode::Op::FloatNeg),
                Op::FloatAbs => (0, pcode::Op::FloatAbs),
                Op::FloatSqrt => (0, pcode::Op::FloatSqrt),
                Op::FloatOfInt => (0, pcode::Op::IntToFloat),
                Op::FloatOfFloat => (0, pcode::Op::FloatToFloat),
                Op::FloatTruncate => (0, pcode::Op::FloatToInt),
                Op::FloatCeiling => (0, pcode::Op::FloatCeiling),
                Op::FloatFloor => (0, pcode::Op::FloatFloor),
                Op::FloatRound => (0, pcode::Op::FloatRound),
                Op::Subpiece => (0, pcode::Op::Subpiece),
                Op::PopCount => (0, pcode::Op::CountOnes),
                Op::LZCount => (0, pcode::Op::CountLeadingZeros),
                _ => unreachable!("state should be unreachable via generated code"),
            };
            Some((index, op))
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct HandleTpl {
    pub space: u16,
    pub size: u16,
    pub ptr_space: u16,
    pub ptr_offset: u16,
    pub ptr_size: u16,
    pub tmp_space: u16,
    pub tmp_offset: u16,
}

#[inline(always)]
pub(crate) fn handle_tpl(data: &'static LanguageData, idx: u16) -> &'static HandleTpl {
    &data.handle_templates[idx as usize]
}

impl HandleTpl {
    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn build(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState,
    ) -> Option<FixedHandle> {
        unsafe {
            let ptr_space = const_tpl(data, self.ptr_space);
            let handle = if ptr_space.is_real() {
                let space = const_tpl(data, self.space).space(data, input);
                let size = const_tpl(data, self.size).value(data, input)? as u16;

                let mut handle = FixedHandle {
                    space,
                    size,
                    ..Default::default()
                };

                const_tpl(data, self.ptr_offset).update_offset(data, input, &mut handle)?;

                handle
            } else {
                let space = const_tpl(data, self.space).space_via(data, input);
                let size = const_tpl(data, self.size).value(data, input)? as u16;

                let offset_offset = const_tpl(data, self.ptr_offset).value(data, input)?;
                let offset_space = ptr_space.space_via(data, input);

                let mut handle = FixedHandle {
                    space,
                    size,
                    offset_offset,
                    offset_space,
                    ..Default::default()
                };

                if offset_space == 0 {
                    let hoffset = data.space_upper_bound(space);
                    let word_size = data.space_word_size(space) as u64;

                    handle.offset_space = INVALID_HANDLE;
                    handle.offset_offset = wrap_offset(hoffset, handle.offset_offset * word_size);
                } else {
                    handle.offset_size = const_tpl(data, self.ptr_size).value(data, input)? as u16;

                    handle.temporary_offset =
                        const_tpl(data, self.tmp_offset).value(data, input)?;
                    handle.temporary_space = const_tpl(data, self.tmp_space).space_via(data, input);
                }

                handle
            };
            Some(handle)
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct VarnodeTpl {
    pub space: u16,
    pub offset: u16,
    pub size: u16,
}

#[inline(always)]
fn varnode_tpl(data: &'static LanguageData, idx: u16) -> &'static VarnodeTpl {
    &data.varnode_templates[idx as usize]
}

#[inline(always)]
fn varnode_tpl_offset(data: &'static LanguageData, idx: u16) -> &'static ConstTpl {
    data.varnode_templates[idx as usize].offset(data)
}

/// # Safety
///
/// Called from generated code which ensures validity of arguments and state.
#[inline(always)]
unsafe fn varnode_tpl_offset_value(
    data: &'static LanguageData,
    idx: u16,
    input: &mut LiftingContextState<'_>,
) -> Option<u64> {
    unsafe { varnode_tpl_offset(data, idx).value(data, input) }
}

impl VarnodeTpl {
    fn offset(&self, data: &'static LanguageData) -> &'static ConstTpl {
        const_tpl(data, self.offset)
    }

    fn is_dynamic(&self, data: &'static LanguageData, input: &LiftingContextState<'_>) -> bool {
        let ConstTpl::Handle(index, _) = const_tpl(data, self.offset) else {
            return false;
        };

        let handle = unsafe { input.operand_handle(*index) };

        handle.offset_space != INVALID_HANDLE
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn location(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<pcode::Varnode> {
        unsafe {
            let space = const_tpl(data, self.space).space_via(data, input);
            let size = const_tpl(data, self.size).value(data, input)? as u16;
            let offset = data.space_location_offset(
                input.unique_offset,
                space,
                const_tpl(data, self.offset).value(data, input)?,
                size,
            );

            Some(pcode::Varnode {
                space,
                offset,
                size,
            })
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn pointer(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<(u8, pcode::Varnode)> {
        unsafe {
            let index = const_tpl(data, self.offset).handle_index().expect("handle");
            let handle = input.operand_handle(index);

            let space = handle.offset_space;
            let size = handle.offset_size;
            let offset =
                data.space_location_offset(input.unique_offset, space, handle.offset_offset, size);

            Some((
                handle.space,
                pcode::Varnode {
                    space,
                    offset,
                    size,
                },
            ))
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn build_input(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
    ) -> Option<()> {
        unsafe {
            let location = self.location(data, input)?;

            if self.is_dynamic(data, input) {
                let (space, pointer) = self.pointer(data, input)?;
                input.issue_with(
                    pcode::Op::Load(space),
                    pcode::Inputs::one(pointer),
                    location,
                );
            }

            input.push_input(location);

            Some(())
        }
    }

    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    pub unsafe fn build_output(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState<'_>,
        op: pcode::Op,
    ) -> Option<()> {
        unsafe {
            let out = self.location(data, input)?;
            input.issue(op, out);

            if self.is_dynamic(data, input) {
                let (space, pointer) = self.pointer(data, input)?;
                input.issue_with(
                    pcode::Op::Store(space),
                    pcode::Inputs::two(pointer, out),
                    pcode::Varnode::INVALID,
                );
            }

            Some(())
        }
    }
}
