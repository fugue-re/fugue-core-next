use crate::input::{FixedHandle, INVALID_HANDLE};
use crate::language::LanguageData;
use crate::{LiftingContextState, pcode, wrap_offset};

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum Op {
    Build,
    DelaySlot,
    Label,
    CrossBuild,
    Issue(pcode::Op),
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
                        ninput.input().next_address()
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
                    let offset = varnode_tpl(data, self.inputs[0]).real_offset(data) as usize;
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
                Op::Issue(op) => self.dump_action(data, input, op),
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
            let index = varnode_tpl(data, self.inputs[0]).real_offset(data) as usize;
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
        op: pcode::Op,
    ) -> Option<()> {
        unsafe {
            let index = matches!(
                op,
                pcode::Op::Load(_) | pcode::Op::Store(_) | pcode::Op::UserOp(..)
            ) as usize;

            for &input in &self.inputs[index..] {
                varnode_tpl(data, input).build_input(data, state)?;
            }

            if self
                .inputs
                .first()
                .is_some_and(|&input| varnode_tpl(data, input).is_relative(data))
            {
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
pub enum VarnodeTpl {
    Fixed { space: u8, offset: u64, size: u16 },
    Computed { space: u16, offset: u16, size: u16 },
}

#[inline(always)]
fn varnode_tpl(data: &'static LanguageData, idx: u16) -> &'static VarnodeTpl {
    &data.varnode_templates[idx as usize]
}

impl VarnodeTpl {
    fn real_offset(&self, data: &'static LanguageData) -> u64 {
        match self {
            Self::Fixed { offset, .. } => *offset,
            Self::Computed { offset, .. } => const_tpl(data, *offset).real(),
        }
    }

    fn is_relative(&self, data: &'static LanguageData) -> bool {
        match self {
            Self::Fixed { .. } => false,
            Self::Computed { offset, .. } => {
                matches!(const_tpl(data, *offset), ConstTpl::Relative(_))
            }
        }
    }

    fn is_dynamic(&self, data: &'static LanguageData, input: &LiftingContextState<'_>) -> bool {
        let Self::Computed { offset, .. } = self else {
            return false;
        };
        let ConstTpl::Handle(index, _) = const_tpl(data, *offset) else {
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
            let (space, offset, size) = match self {
                Self::Fixed {
                    space,
                    offset,
                    size,
                } => (*space, *offset, *size),
                Self::Computed {
                    space,
                    offset,
                    size,
                } => (
                    const_tpl(data, *space).space_via(data, input),
                    const_tpl(data, *offset).value(data, input)?,
                    const_tpl(data, *size).value(data, input)? as u16,
                ),
            };
            let offset = data.space_location_offset(input.unique_offset, space, offset, size);

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
            let Self::Computed { offset, .. } = self else {
                return None;
            };
            let index = const_tpl(data, *offset).handle_index().expect("handle");
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
