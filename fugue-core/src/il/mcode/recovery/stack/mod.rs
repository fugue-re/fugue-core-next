use rustc_hash::FxHashMap;

use super::abi::MCodeStorageFact;
use crate::il::common::{IlArtefact, IlCsr, IlOpId, IlValueId, RegisterId};
use crate::il::ecode::{ECodeBlockArgInputs, ECodeDomain, ECodeIr, ECodeOpcode, ECodeUses};
use crate::il::mcode::MCodeStorageLocation;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum StackOffset {
    Fixed(i64),
    Unknown,
    Unvisited,
}

impl StackOffset {
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unvisited, other) => other,
            (this, Self::Unvisited) => this,
            (Self::Fixed(a), Self::Fixed(b)) if a == b => Self::Fixed(a),
            _ => Self::Unknown,
        }
    }

    fn shift(self, displacement: i64) -> Self {
        match self {
            Self::Fixed(base) => match base.checked_add(displacement) {
                Some(offset) => Self::Fixed(offset),
                None => Self::Unknown,
            },
            other => other,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct MCodeStackObject {
    start: i64,
    end: i64,
    address_taken: bool,
}

impl MCodeStackObject {
    const fn new(start: i64, end: i64, address_taken: bool) -> Self {
        Self {
            start,
            end,
            address_taken,
        }
    }

    fn from_interval(interval: StackObjectInterval) -> Self {
        Self::new(interval.start, interval.end, interval.address_taken)
    }

    fn merge_interval(&mut self, interval: StackObjectInterval) -> bool {
        if interval.start >= self.end {
            return false;
        }
        self.end = self.end.max(interval.end);
        self.address_taken |= interval.address_taken;
        true
    }

    pub(crate) const fn start(&self) -> i64 {
        self.start
    }

    pub(crate) const fn address_taken(&self) -> bool {
        self.address_taken
    }

    pub(crate) fn width(&self) -> Option<u32> {
        self.end
            .checked_sub(self.start)
            .and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bits| u32::try_from(bits).ok())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub(crate) struct MCodeStackObjectId(usize);

impl MCodeStackObjectId {
    pub(crate) const fn from_index(index: usize) -> Self {
        Self(index)
    }

    pub(crate) const fn index(&self) -> usize {
        self.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct MCodeStackAccess {
    object: MCodeStackObjectId,
    field_offset: u64,
}

impl MCodeStackAccess {
    const fn new(object: MCodeStackObjectId, field_offset: u64) -> Self {
        Self {
            object,
            field_offset,
        }
    }

    pub(crate) const fn object(&self) -> MCodeStackObjectId {
        self.object
    }

    pub(crate) const fn field_offset(&self) -> u64 {
        self.field_offset
    }
}

#[derive(Debug, Copy, Clone)]
struct StackObjectInterval {
    start: i64,
    end: i64,
    site: Option<IlOpId>,
    address_taken: bool,
}

impl StackObjectInterval {
    const fn access(start: i64, end: i64, site: IlOpId) -> Self {
        Self {
            start,
            end,
            site: Some(site),
            address_taken: false,
        }
    }

    fn address(start: i64) -> Option<Self> {
        Some(Self {
            start,
            end: start.checked_add(1)?,
            site: None,
            address_taken: true,
        })
    }

    fn storage(fact: MCodeStorageFact) -> Option<Self> {
        let MCodeStorageLocation::Stack { offset } = fact.location() else {
            return None;
        };
        Some(Self {
            start: offset,
            end: offset.checked_add(i64::from(fact.width().div_ceil(8)))?,
            site: None,
            address_taken: true,
        })
    }
}

#[derive(Debug)]
pub(crate) struct MCodeStackModel {
    offsets: Vec<StackOffset>,
    objects: Vec<MCodeStackObject>,
    accesses: FxHashMap<IlOpId, MCodeStackAccess>,
    addresses: FxHashMap<IlValueId, MCodeStackAccess>,
}

impl MCodeStackModel {
    pub(crate) fn new(
        ir: &ECodeIr,
        stack_pointer: RegisterId,
        storage: impl IntoIterator<Item = MCodeStorageFact>,
    ) -> Self {
        let block_arg_inputs = ir.analyse::<ECodeBlockArgInputs>();
        let entry_stack_pointer = (0..ir.values().len())
            .map(|index| IlValueId::try_from_index(index).expect("value id is representable"))
            .find(|&value| {
                ir.value_domain(value) == Some(ECodeDomain::Register(stack_pointer))
                    && ir
                        .defining_op(value)
                        .is_some_and(|operation| operation.opcode() == ECodeOpcode::Undefined)
            });
        let mut this = Self {
            offsets: vec![StackOffset::Unvisited; ir.values().len()],
            objects: Vec::new(),
            accesses: FxHashMap::default(),
            addresses: FxHashMap::default(),
        };

        let dependents = IlCsr::from_entries(
            ir.values().len(),
            block_arg_inputs.iter().flat_map(|(arg, inputs)| {
                inputs.iter().map(move |input| (input.index(), arg.index()))
            }),
        );

        let uses = ir.analyse::<ECodeUses>();
        let mut worklist = (0..ir.values().len()).rev().collect::<Vec<_>>();

        while let Some(index) = worklist.pop() {
            let value = IlValueId::try_from_index(index).expect("value id is representable");
            let next = match block_arg_inputs.inputs_for(value) {
                Some([]) => StackOffset::Unknown,
                Some(inputs) => inputs
                    .iter()
                    .fold(StackOffset::Unvisited, |accumulated, input| {
                        accumulated.join(this.offsets[input.index()])
                    }),
                None => this.evaluate(ir, value, stack_pointer, entry_stack_pointer),
            };

            if next == this.offsets[index] {
                continue;
            }
            this.offsets[index] = next;

            for use_site in uses.uses_for(value) {
                let user = &ir.ops()[use_site.user().index()];
                worklist.extend(user.results().start()..user.results().end());
            }
            worklist.extend(dependents.row(index));
        }

        this.discover_objects(ir, &uses, storage);

        this
    }

    pub(crate) fn offset_of(&self, value: IlValueId) -> Option<i64> {
        match self.offsets.get(value.index()) {
            Some(StackOffset::Fixed(displacement)) => Some(*displacement),
            _ => None,
        }
    }

    pub(crate) fn objects(&self) -> &[MCodeStackObject] {
        &self.objects
    }

    pub(crate) fn access_for(&self, operation: IlOpId) -> Option<MCodeStackAccess> {
        self.accesses.get(&operation).copied()
    }

    pub(crate) fn address_for(&self, value: IlValueId) -> Option<MCodeStackAccess> {
        self.addresses.get(&value).copied()
    }

    pub(crate) fn storage_access(&self, offset: i64, width: u32) -> Option<MCodeStackAccess> {
        let end = offset.checked_add(i64::from(width.div_ceil(8)))?;
        let object_index = self.objects.partition_point(|object| object.end <= offset);
        let object = self
            .objects
            .get(object_index)
            .filter(|object| object.start <= offset && end <= object.end)?;
        let field_offset = offset
            .checked_sub(object.start)
            .and_then(|bytes| u64::try_from(bytes).ok())?
            .checked_mul(8)?;
        Some(MCodeStackAccess::new(
            MCodeStackObjectId::from_index(object_index),
            field_offset,
        ))
    }

    fn discover_objects(
        &mut self,
        ir: &ECodeIr,
        uses: &ECodeUses,
        storage: impl IntoIterator<Item = MCodeStorageFact>,
    ) {
        let mut intervals = self.collect_intervals(ir);
        intervals.extend(storage.into_iter().filter_map(StackObjectInterval::storage));
        let exposed = self.collect_exposure(ir, uses, &mut intervals);

        intervals.sort_by_key(|interval| interval.start);
        for &interval in &intervals {
            if self
                .objects
                .last_mut()
                .is_some_and(|object| object.merge_interval(interval))
            {
                continue;
            }
            self.objects.push(MCodeStackObject::from_interval(interval));
        }

        for interval in &intervals {
            let Some(site) = interval.site else {
                continue;
            };
            let object_index = self
                .objects
                .partition_point(|object| object.end <= interval.start);
            let Some(record) = self
                .objects
                .get(object_index)
                .filter(|record| record.start <= interval.start && interval.end <= record.end)
            else {
                continue;
            };
            let Some(field_offset) = interval
                .start
                .checked_sub(record.start)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .and_then(|bytes| bytes.checked_mul(8))
            else {
                continue;
            };
            self.accesses.insert(
                site,
                MCodeStackAccess::new(MCodeStackObjectId::from_index(object_index), field_offset),
            );
        }

        for (value, offset) in exposed {
            let object_index = self.objects.partition_point(|object| object.end <= offset);
            let Some(record) = self
                .objects
                .get(object_index)
                .filter(|record| record.start <= offset && offset < record.end)
            else {
                continue;
            };
            let Some(field_offset) = offset
                .checked_sub(record.start)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .and_then(|bytes| bytes.checked_mul(8))
            else {
                continue;
            };
            self.addresses.insert(
                value,
                MCodeStackAccess::new(MCodeStackObjectId::from_index(object_index), field_offset),
            );
        }
    }

    fn collect_intervals(&self, ir: &ECodeIr) -> Vec<StackObjectInterval> {
        let mut intervals = Vec::new();
        for (index, operation) in ir.ops().iter().enumerate() {
            if !matches!(operation.opcode(), ECodeOpcode::Load | ECodeOpcode::Store) {
                continue;
            }
            let Some(pointer) = ir.pointer_operand(operation) else {
                continue;
            };
            let Some(start) = self.offset_of(ir.underlying_value(pointer)) else {
                continue;
            };
            let width = match operation.opcode() {
                ECodeOpcode::Load => operation.width(),
                _ => ir
                    .op_operands_for(operation)
                    .get(1)
                    .and_then(|value| ir.value_width(*value))
                    .unwrap_or(0),
            };
            let Some(end) = start.checked_add(i64::from(width.div_ceil(8))) else {
                continue;
            };
            let site = IlOpId::try_from_index(index).expect("operation id is representable");
            intervals.push(StackObjectInterval::access(start, end, site));
        }
        intervals
    }

    fn collect_exposure(
        &self,
        ir: &ECodeIr,
        uses: &ECodeUses,
        intervals: &mut Vec<StackObjectInterval>,
    ) -> Vec<(IlValueId, i64)> {
        let mut exposed = Vec::new();
        for index in 0..ir.values().len() {
            let value = IlValueId::try_from_index(index).expect("value id is representable");
            let Some(offset) = self.offset_of(value) else {
                continue;
            };
            let exposed_here = uses.uses_for(value).iter().any(|site| {
                let user = &ir.ops()[site.user().index()];
                match user.opcode() {
                    ECodeOpcode::Load | ECodeOpcode::Store if site.operand_index() == 0 => false,
                    ECodeOpcode::Copy
                    | ECodeOpcode::WriteFlag
                    | ECodeOpcode::WriteRegister
                    | ECodeOpcode::Add
                    | ECodeOpcode::Sub => {
                        let result = IlValueId::try_from_index(user.results().start())
                            .expect("value id is representable");
                        self.offset_of(result).is_none()
                    }
                    _ => true,
                }
            });
            if exposed_here {
                exposed.push((value, offset));
            }
        }

        for (_, offset) in &exposed {
            intervals.extend(StackObjectInterval::address(*offset));
        }

        exposed
    }

    fn evaluate(
        &self,
        ir: &ECodeIr,
        value: IlValueId,
        stack_pointer: RegisterId,
        entry_stack_pointer: Option<IlValueId>,
    ) -> StackOffset {
        let Some(operation) = ir.defining_op(value) else {
            return StackOffset::Unvisited;
        };

        if operation.opcode() == ECodeOpcode::Undefined {
            return if ir.value_domain(value) != Some(ECodeDomain::Register(stack_pointer)) {
                StackOffset::Unvisited
            } else if Some(value) == entry_stack_pointer {
                StackOffset::Fixed(0)
            } else {
                StackOffset::Unknown
            };
        }

        let operands = ir.op_operands_for(operation);
        let offset = |index: usize| {
            operands
                .get(index)
                .map(|operand| self.offsets[operand.index()])
        };
        let displacement = |index: usize| {
            operands
                .get(index)
                .and_then(|operand| ir.constant_value(*operand))
                .and_then(|constant| constant.signed_cast(64).to_u64())
                .map(|value| i64::from_ne_bytes(value.to_ne_bytes()))
        };

        let affine = match operation.opcode() {
            ECodeOpcode::Copy | ECodeOpcode::WriteFlag | ECodeOpcode::WriteRegister => {
                return offset(0).unwrap_or(StackOffset::Unvisited);
            }
            ECodeOpcode::Add => offset(0)
                .zip(displacement(1))
                .or_else(|| offset(1).zip(displacement(0)))
                .map(|(base, displacement)| base.shift(displacement)),
            ECodeOpcode::Sub => offset(0).zip(displacement(1)).map(|(base, displacement)| {
                match displacement.checked_neg() {
                    Some(negated) => base.shift(negated),
                    None => StackOffset::Unknown,
                }
            }),
            _ => None,
        };

        affine.unwrap_or_else(|| {
            if operands
                .iter()
                .any(|operand| self.offsets[operand.index()] != StackOffset::Unvisited)
            {
                StackOffset::Unknown
            } else {
                StackOffset::Unvisited
            }
        })
    }
}

#[cfg(test)]
mod test;
