use crate::constructor::ConstructorResolver;
use crate::input::{FixedHandle, INVALID_HANDLE};
use crate::{pcode, wrap_offset, LiftingContextState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub delay_slot: u8, // usize
    pub labels: u8,
    pub result: Option<u16>,        // HandleTpl
    pub operations: &'static [u16], // OpTpl
}

impl ConstructTpl {
    #[inline]
    pub unsafe fn build<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
    ) -> Option<()> {
        let old_base = input.context.label_base;

        input.context.label_base = input.context.label_count;
        input.context.label_count += self.labels;

        for &operation in self.operations {
            op_tpl::<R>(operation).build::<R>(input)?;
        }

        input.context.label_base = old_base;

        Some(())
    }

    pub unsafe fn build_result<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
    ) -> Option<FixedHandle> {
        self.result
            .and_then(|handle| handle_tpl::<R>(handle).build::<R>(input))
    }
}

#[derive(Debug)]
pub enum HandleKind {
    Space,
    Offset,
    Size,
    OffsetPlus(u64),
}

#[derive(Debug)]
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
fn const_tpl<R: ConstructorResolver>(idx: u16) -> &'static ConstTpl {
    &R::CONST_TEMPLATES[idx as usize]
}

impl ConstTpl {
    #[inline]
    pub unsafe fn update_offset<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
        handle: &mut FixedHandle,
    ) -> Option<()> {
        match self {
            Self::Handle(index, _) => {
                let h = unsafe { input.operand_handle_mut(*index) };

                handle.offset_space = h.offset_space;
                handle.offset_offset = h.offset_offset;
                handle.offset_size = h.offset_size;
                handle.temporary_space = h.temporary_space;
                handle.temporary_offset = h.temporary_offset;
            }
            _ => {
                let value = self.value::<R>(input)?;

                handle.offset_space = INVALID_HANDLE;
                handle.offset_offset = wrap_offset(R::resolve_upper_bound(handle.space), value);
            }
        }
        Some(())
    }

    // fix space
    #[inline]
    pub unsafe fn space_via<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
    ) -> u8 {
        match self {
            Self::CurrentSpace => R::DEFAULT_SPACE,
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

    // fix space
    #[inline]
    pub unsafe fn space<R: ConstructorResolver>(&self, input: &mut LiftingContextState<'_>) -> u8 {
        match self {
            Self::CurrentSpace => R::DEFAULT_SPACE,
            Self::Handle(index, HandleKind::Space) => {
                let handle = input.input().operand_handle(*index);
                handle.space
            }
            Self::SpaceId(id) => *id,
            _ => unreachable!("state should be unreachable via generated code"),
        }
    }

    #[inline]
    pub unsafe fn value<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
    ) -> Option<u64> {
        let value = match self {
            ConstTpl::Start => input.address(),
            ConstTpl::Next => input.next_address(),
            ConstTpl::Next2 => {
                if let Some(next2_address) = input.next2_address() {
                    next2_address
                } else {
                    let mut ninput = input.next_input()?;
                    R::resolve(&mut ninput)?;
                    ninput.next_address()
                }
            }
            ConstTpl::CurrentSpaceSize => R::ADDRESS_SIZE as u64,
            ConstTpl::CurrentSpace => R::DEFAULT_SPACE as u64,
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
                            // constant space
                            let val = if handle.offset_space == INVALID_HANDLE {
                                handle.offset_offset
                            } else {
                                handle.temporary_offset
                            };
                            val.checked_shr(value_shift).unwrap_or(0)
                        } else {
                            if handle.offset_space == INVALID_HANDLE {
                                handle.offset_offset + value_short
                            } else {
                                handle.temporary_offset + value_short
                            }
                        }
                    }
                }
            }
        };
        Some(value)
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
    pub inputs: &'static [u16], // VarnodeTpl
    pub output: Option<u16>,    // VarnodeTpl
}

#[inline(always)]
fn op_tpl<R: ConstructorResolver>(idx: u16) -> &'static OpTpl {
    &R::OP_TEMPLATES[idx as usize]
}

impl OpTpl {
    pub unsafe fn build<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState,
    ) -> Option<()> {
        match self.op {
            Op::Build => self.append_build_action::<R>(input),
            Op::DelaySlot => self.delay_slot_action::<R>(input),
            Op::Label => {
                // NOTE: the original logic here checks if the index exceeds the current
                // size of the allocated labels, and if so, then creates a range of invalid
                // labels. Since we have a fixed allocation, we get this by default, so we
                // can just set the label value.
                //
                let offset = varnode_tpl_offset::<R>(self.inputs[0]).real() as usize;
                unsafe {
                    *input
                        .context
                        .labels
                        .get_unchecked_mut(offset + input.context.label_base as usize) =
                        input.issued.len() as i16;
                }
                Some(())
            }
            Op::CrossBuild => {
                unimplemented!("cross-build is not supported")
            }
            _ => self.dump_action::<R>(input),
        }
    }

    pub unsafe fn append_build_action<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState,
    ) -> Option<()> {
        let index = varnode_tpl_offset::<R>(self.inputs[0]).real() as usize;
        if let Some(operand) = unsafe { input.operand_constructor(index) } {
            input.input().push_operand(index);

            if let Some(builder) = &operand.build_action {
                builder.build::<R>(input)?;
            }

            input.input().pop_operand();
        }
        Some(())
    }

    pub unsafe fn delay_slot_action<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState,
    ) -> Option<()> {
        input.emit_delay_slots::<R>()
    }

    pub unsafe fn dump_action<R: ConstructorResolver>(
        &self,
        state: &mut LiftingContextState,
    ) -> Option<()> {
        let (index, op) = self.build_op::<R>(state)?;

        for &input in &self.inputs[index..] {
            varnode_tpl::<R>(input).build_input::<R>(state)?;
        }

        if !self.inputs.is_empty() {
            state.context.inputs.0[0].offset += state.context.label_base as u64;
            state.context.label_refs.push(pcode::RelativeRecord {
                operation: state.issued.len() as u8,
                index: 0,
            });
        }

        let Some(output) = self.output.map(varnode_tpl::<R>) else {
            state.issue(op, pcode::Varnode::INVALID);
            return Some(());
        };

        output.build_output::<R>(state, op)
    }

    #[inline]
    unsafe fn build_op<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
    ) -> Option<(usize, pcode::Op)> {
        let (index, op) = match self.op {
            Op::Load => {
                let space = varnode_tpl_offset_value::<R>(self.inputs[0], input)? as u8;
                (1, pcode::Op::Load(space))
            }
            Op::Store => {
                let space = varnode_tpl_offset_value::<R>(self.inputs[0], input)? as u8;
                (1, pcode::Op::Store(space))
            }
            Op::CallOther => {
                // NOTE: we could resolve the UserOp here at the cost of a larger
                // representation for Op...
                let index = varnode_tpl_offset_value::<R>(self.inputs[0], input)? as u16;
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

#[derive(Debug)]
pub struct HandleTpl {
    pub space: u16,      // ConstTpl
    pub size: u16,       // ConstTpl
    pub ptr_space: u16,  // ConstTpl
    pub ptr_offset: u16, // ConstTpl
    pub ptr_size: u16,   // ConstTpl
    pub tmp_space: u16,  // ConstTpl
    pub tmp_offset: u16, // ConstTpl
}

#[inline(always)]
fn handle_tpl<R: ConstructorResolver>(idx: u16) -> &'static HandleTpl {
    &R::HANDLE_TEMPLATES[idx as usize]
}

impl HandleTpl {
    pub unsafe fn build<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState,
    ) -> Option<FixedHandle> {
        let ptr_space = const_tpl::<R>(self.ptr_space);
        let handle = if ptr_space.is_real() {
            let space = const_tpl::<R>(self.space).space::<R>(input);
            let size = const_tpl::<R>(self.size).value::<R>(input)? as u16;

            let mut handle = FixedHandle {
                space,
                size,
                ..Default::default()
            };

            const_tpl::<R>(self.ptr_offset).update_offset::<R>(input, &mut handle)?;

            handle
        } else {
            let space = const_tpl::<R>(self.space).space_via::<R>(input);
            let size = const_tpl::<R>(self.size).value::<R>(input)? as u16;

            let offset_offset = const_tpl::<R>(self.ptr_offset).value::<R>(input)?;
            let offset_space = ptr_space.space_via::<R>(input);

            let mut handle = FixedHandle {
                space,
                size,
                offset_offset,
                offset_space,
                ..Default::default()
            };

            if offset_space == 0 {
                let hoffset = R::resolve_upper_bound(space);
                let word_size = R::resolve_word_size(space) as u64;

                handle.offset_space = INVALID_HANDLE;
                handle.offset_offset = wrap_offset(hoffset, handle.offset_offset * word_size);
            } else {
                handle.offset_size = const_tpl::<R>(self.ptr_size).value::<R>(input)? as u16;

                handle.temporary_offset = const_tpl::<R>(self.tmp_offset).value::<R>(input)?;
                handle.temporary_space = const_tpl::<R>(self.tmp_space).space_via::<R>(input);
            }

            handle
        };
        Some(handle)
    }
}

#[derive(Debug)]
pub struct VarnodeTpl {
    pub space: u16,  // ConstTpl
    pub offset: u16, // ConstTpl
    pub size: u16,   // ConstTpl
}

#[inline(always)]
fn varnode_tpl<R: ConstructorResolver>(idx: u16) -> &'static VarnodeTpl {
    &R::VARNODE_TEMPLATES[idx as usize]
}

#[inline(always)]
fn varnode_tpl_offset<R: ConstructorResolver>(idx: u16) -> &'static ConstTpl {
    R::VARNODE_TEMPLATES[idx as usize].offset::<R>()
}

#[inline(always)]
unsafe fn varnode_tpl_offset_value<R: ConstructorResolver>(
    idx: u16,
    input: &mut LiftingContextState<'_>,
) -> Option<u64> {
    varnode_tpl_offset::<R>(idx).value::<R>(input)
}

impl VarnodeTpl {
    fn offset<R: ConstructorResolver>(&self) -> &'static ConstTpl {
        const_tpl::<R>(self.offset)
    }

    fn is_dynamic<R: ConstructorResolver>(&self, input: &LiftingContextState<'_>) -> bool {
        let ConstTpl::Handle(index, _) = const_tpl::<R>(self.offset) else {
            return false;
        };

        let handle = unsafe { input.operand_handle(*index) };

        handle.offset_space != INVALID_HANDLE
    }

    pub unsafe fn location<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
    ) -> Option<pcode::Varnode> {
        let space = const_tpl::<R>(self.space).space_via::<R>(input);
        let size = const_tpl::<R>(self.size).value::<R>(input)? as u16;
        let offset = R::resolve_location_offset(
            input.unique_offset,
            space,
            const_tpl::<R>(self.offset).value::<R>(input)?,
            size,
        );

        Some(pcode::Varnode {
            space,
            offset,
            size,
        })
    }

    pub unsafe fn pointer<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
    ) -> Option<(u8, pcode::Varnode)> {
        let index = const_tpl::<R>(self.offset).handle_index().expect("handle");
        let handle = input.operand_handle(index);

        let space = handle.offset_space;
        let size = handle.offset_size;
        let offset =
            R::resolve_location_offset(input.unique_offset, space, handle.offset_offset, size);

        Some((
            handle.space,
            pcode::Varnode {
                space,
                offset,
                size,
            },
        ))
    }

    pub unsafe fn build_input<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
    ) -> Option<()> {
        let location = self.location::<R>(input)?;

        if self.is_dynamic::<R>(input) {
            let (space, pointer) = self.pointer::<R>(input)?;
            input.issue_with(
                pcode::Op::Load(space),
                pcode::Inputs::one(pointer),
                location,
            );
        }

        input.push_input(location);

        Some(())
    }

    pub unsafe fn build_output<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState<'_>,
        op: pcode::Op,
    ) -> Option<()> {
        let out = self.location::<R>(input)?;
        input.issue(op, out);

        if self.is_dynamic::<R>(input) {
            let (space, pointer) = self.pointer::<R>(input)?;
            input.issue_with(
                pcode::Op::Store(space),
                pcode::Inputs::two(pointer, out),
                pcode::Varnode::INVALID,
            );
        }

        Some(())
    }
}
