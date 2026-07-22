use fugue_bv::BitVec;
use rustc_hash::FxHashMap;

use crate::ir::RawAddress;
use crate::lifter::{Op, PCodeOp, Varnode};

fn constant_and_value(a: Varnode, b: Varnode) -> Option<(u64, Varnode)> {
    if a.is_constant() && !b.is_constant() {
        Some((a.offset(), b))
    } else if b.is_constant() && !a.is_constant() {
        Some((b.offset(), a))
    } else {
        None
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct SwitchOffsetBase {
    address: RawAddress,
    signed: bool,
}

impl SwitchOffsetBase {
    pub(crate) fn address(&self) -> RawAddress {
        self.address
    }

    pub(crate) fn is_signed(&self) -> bool {
        self.signed
    }
}

struct SwitchTableMatch {
    table: RawAddress,
    base: Option<SwitchOffsetBase>,
    element_size: u32,
    shift: u8,
    index: Varnode,
    index_before: usize,
}

struct SwitchLoadedOffset {
    table: RawAddress,
    index: Varnode,
    element_size: u32,
    signed: bool,
    index_before: usize,
    shift: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SwitchIdiomMatch {
    table: RawAddress,
    base: Option<SwitchOffsetBase>,
    element_size: u32,
    shift: u8,
    bound: Option<BitVec>,
    label_offset: i64,
}

impl SwitchIdiomMatch {
    pub(crate) fn table(&self) -> RawAddress {
        self.table
    }

    pub(crate) fn base(&self) -> Option<SwitchOffsetBase> {
        self.base
    }

    pub(crate) fn element_size(&self) -> u32 {
        self.element_size
    }

    pub(crate) fn shift(&self) -> u8 {
        self.shift
    }

    pub(crate) fn bound(&self) -> Option<&BitVec> {
        self.bound.as_ref()
    }

    pub(crate) fn label_offset(&self) -> i64 {
        self.label_offset
    }
}

pub(crate) struct SwitchIdiomMatcher<'a> {
    operations: &'a [PCodeOp],
    definitions: FxHashMap<Varnode, Vec<usize>>,
    branch: usize,
    max_trace_depth: u32,
}

impl<'a> SwitchIdiomMatcher<'a> {
    pub(crate) fn new(operations: &'a [PCodeOp], max_trace_depth: u32) -> Option<Self> {
        let branch = operations
            .iter()
            .rposition(|operation| matches!(operation.op(), Op::IBranch))?;
        let mut definitions = FxHashMap::<Varnode, Vec<usize>>::default();
        for (index, operation) in operations[..branch].iter().enumerate() {
            if let Some(output) = operation.output() {
                definitions.entry(*output).or_default().push(index);
            }
        }
        Some(Self {
            operations,
            definitions,
            branch,
            max_trace_depth,
        })
    }

    pub(crate) fn match_idiom(&self) -> Option<SwitchIdiomMatch> {
        let table = self.match_table()?;
        Some(SwitchIdiomMatch {
            table: table.table,
            base: table.base,
            element_size: table.element_size,
            shift: table.shift,
            bound: self.guard_bound(table.index),
            label_offset: self.label_offset(table.index, table.index_before),
        })
    }

    fn defining_operation(&self, varnode: &Varnode, before: usize) -> Option<(usize, &PCodeOp)> {
        let index = *self
            .definitions
            .get(varnode)?
            .iter()
            .rev()
            .find(|&&index| index < before)?;
        Some((index, &self.operations[index]))
    }

    fn match_table(&self) -> Option<SwitchTableMatch> {
        let mut target = self.operations[self.branch].inputs().first().copied()?;
        let mut before = self.branch;
        for _ in 0..self.max_trace_depth {
            let (index, defining) = self.defining_operation(&target, before)?;
            match defining.op() {
                Op::Load(_) => {
                    let pointer = defining.inputs().first().copied()?;
                    let (table, table_index, index_before) = self.match_pointer(&pointer, index)?;
                    return Some(SwitchTableMatch {
                        table,
                        base: None,
                        element_size: u32::try_from(target.size()).ok()?,
                        shift: 0,
                        index: table_index,
                        index_before,
                    });
                }
                Op::IntAdd => {
                    let a = defining.inputs().first().copied()?;
                    let b = defining.inputs().get(1).copied()?;
                    return self
                        .match_offset_relative(&a, &b, index)
                        .or_else(|| self.match_offset_relative(&b, &a, index));
                }
                Op::Copy => {
                    target = defining.inputs().first().copied()?;
                    before = index;
                }
                _ => return None,
            }
        }
        None
    }

    fn match_pointer(
        &self,
        pointer: &Varnode,
        before: usize,
    ) -> Option<(RawAddress, Varnode, usize)> {
        let (index, defining) = self.defining_operation(pointer, before)?;
        if !matches!(defining.op(), Op::IntAdd) {
            return None;
        }
        let a = defining.inputs().first().copied()?;
        let b = defining.inputs().get(1).copied()?;
        let (table, scaled) = constant_and_value(a, b)?;
        let (index, index_before) = self.strip_index(&scaled, index);
        Some((RawAddress::from(table), index, index_before))
    }

    fn strip_index(&self, scaled: &Varnode, before: usize) -> (Varnode, usize) {
        let mut current = *scaled;
        let mut before = before;
        for _ in 0..self.max_trace_depth {
            let Some((index, defining)) = self.defining_operation(&current, before) else {
                return (current, before);
            };
            match defining.op() {
                Op::IntMul | Op::IntLeftShift => {
                    let Some((_, variable)) = defining
                        .inputs()
                        .first()
                        .copied()
                        .zip(defining.inputs().get(1).copied())
                        .and_then(|(a, b)| constant_and_value(a, b))
                    else {
                        return (current, before);
                    };
                    current = variable;
                    before = index;
                }
                Op::ZeroExt | Op::SignExt | Op::Copy => {
                    let Some(source) = defining.inputs().first().copied() else {
                        return (current, before);
                    };
                    current = source;
                    before = index;
                }
                _ => return (current, before),
            }
        }
        (current, before)
    }

    fn match_offset_relative(
        &self,
        base: &Varnode,
        offset: &Varnode,
        before: usize,
    ) -> Option<SwitchTableMatch> {
        let loaded = self.match_loaded_offset(offset, before)?;
        Some(SwitchTableMatch {
            table: loaded.table,
            base: Some(SwitchOffsetBase {
                address: self.resolve_constant(base, before)?,
                signed: loaded.signed,
            }),
            element_size: loaded.element_size,
            shift: loaded.shift,
            index: loaded.index,
            index_before: loaded.index_before,
        })
    }

    fn match_loaded_offset(&self, value: &Varnode, before: usize) -> Option<SwitchLoadedOffset> {
        let mut current = *value;
        let mut before = before;
        let mut signed = false;
        let mut shift = 0u8;
        for _ in 0..self.max_trace_depth {
            let (index, defining) = self.defining_operation(&current, before)?;
            match defining.op() {
                Op::SignExt => {
                    signed = true;
                    current = defining.inputs().first().copied()?;
                    before = index;
                }
                Op::ZeroExt | Op::Copy => {
                    current = defining.inputs().first().copied()?;
                    before = index;
                }
                Op::IntLeftShift => {
                    let a = defining.inputs().first().copied()?;
                    let b = defining.inputs().get(1).copied()?;
                    if !b.is_constant() {
                        return None;
                    }
                    shift = shift.checked_add(u8::try_from(b.offset()).ok()?)?;
                    current = a;
                    before = index;
                }
                Op::IntMul => {
                    let a = defining.inputs().first().copied()?;
                    let b = defining.inputs().get(1).copied()?;
                    let (constant, variable) = constant_and_value(a, b)?;
                    if !constant.is_power_of_two() {
                        return None;
                    }
                    shift = shift.checked_add(u8::try_from(constant.trailing_zeros()).ok()?)?;
                    current = variable;
                    before = index;
                }
                Op::Load(_) => {
                    let pointer = defining.inputs().first().copied()?;
                    let (table, table_index, index_before) = self.match_pointer(&pointer, index)?;
                    return Some(SwitchLoadedOffset {
                        table,
                        index: table_index,
                        element_size: u32::try_from(current.size()).ok()?,
                        signed,
                        index_before,
                        shift,
                    });
                }
                _ => return None,
            }
        }
        None
    }

    fn resolve_constant(&self, varnode: &Varnode, before: usize) -> Option<RawAddress> {
        let mut current = *varnode;
        let mut before = before;
        let mut accumulated = RawAddress::from(0u64);
        for _ in 0..self.max_trace_depth {
            if current.is_constant() {
                return Some(accumulated + RawAddress::from(current.offset()));
            }
            let (index, defining) = self.defining_operation(&current, before)?;
            match defining.op() {
                Op::Copy => {
                    current = defining.inputs().first().copied()?;
                    before = index;
                }
                Op::IntAdd => {
                    let a = defining.inputs().first().copied()?;
                    let b = defining.inputs().get(1).copied()?;
                    let (constant, variable) = constant_and_value(a, b)?;
                    accumulated += RawAddress::from(constant);
                    current = variable;
                    before = index;
                }
                _ => return None,
            }
        }
        None
    }

    fn guard_bound(&self, index: Varnode) -> Option<BitVec> {
        for operation in self.operations {
            let inclusive = match operation.op() {
                Op::IntLess | Op::IntSignedLess => false,
                Op::IntLessEq | Op::IntSignedLessEq => true,
                _ => continue,
            };
            let a = operation.inputs().first().copied();
            let b = operation.inputs().get(1).copied();
            let (Some(a), Some(b)) = (a, b) else {
                continue;
            };
            if a != index || !b.is_constant() {
                continue;
            }
            let limit = BitVec::from_u64(b.offset(), u32::try_from(b.size()).ok()? * 8);
            return if inclusive {
                Some(limit)
            } else if limit.is_zero() {
                None
            } else {
                Some(limit.pred())
            };
        }
        None
    }

    fn label_offset(&self, index: Varnode, before: usize) -> i64 {
        let Some((_, operation)) = self.defining_operation(&index, before) else {
            return 0;
        };
        let (Some(a), Some(b)) = (
            operation.inputs().first().copied(),
            operation.inputs().get(1).copied(),
        ) else {
            return 0;
        };
        let Some((constant, _)) = constant_and_value(a, b) else {
            return 0;
        };
        match operation.op() {
            Op::IntSub => constant as i64,
            Op::IntAdd => (constant as i64).wrapping_neg(),
            _ => 0,
        }
    }
}
