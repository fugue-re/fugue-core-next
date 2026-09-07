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

    fn merge_interval(&mut self, interval: StackObjectInterval) -> bool {
        if interval.start >= self.end {
            return false;
        }
        self.end = self.end.max(interval.end);
        self.address_taken |= interval.address_taken;
        true
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

    pub(crate) fn objects(&self) -> &[MCodeStackObject] {
        &self.objects
    }

    pub(crate) fn access_for(&self, operation: IlOpId) -> Option<MCodeStackAccess> {
        self.accesses.get(&operation).copied()
    }

    pub(crate) fn address_for(&self, value: IlValueId) -> Option<MCodeStackAccess> {
        self.addresses.get(&value).copied()
    }

    pub(crate) fn offset_of(&self, value: IlValueId) -> Option<i64> {
        match self.offsets.get(value.index()) {
            Some(StackOffset::Fixed(displacement)) => Some(*displacement),
            _ => None,
        }
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
mod test {
    use super::*;
    use crate::il::common::{
        IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGraph, IlIndexRange,
        IlMetadata, IlOpId, IlValueId,
    };
    use crate::il::ecode::{ECodeBuilder, ECodeOpSpec};
    use crate::ir::FunctionId;
    use crate::storage::segments::space::AddressSpaceId;

    const STACK_POINTER: u64 = 0x20;

    fn emit_value(
        builder: &mut ECodeBuilder,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let (_, results) = builder.emitter().emit(spec, operands, 1)?;
        IlValueId::try_from_index(results.start())
    }

    fn builder() -> ECodeBuilder {
        ECodeBuilder::new(
            IlMetadata::new(FunctionId::default(), 0),
            IlGraph::default(),
        )
    }

    fn push_constant(builder: &mut ECodeBuilder, value: u64) -> IlValueId {
        emit_value(
            builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(value),
            [],
        )
        .unwrap()
    }

    fn push_entry_stack_pointer(builder: &mut ECodeBuilder) -> IlValueId {
        let id = emit_value(builder, ECodeOpSpec::new(ECodeOpcode::Undefined, 64), []).unwrap();
        builder
            .emitter()
            .set_value_domain(id, ECodeDomain::Register(RegisterId::new(STACK_POINTER)))
            .unwrap();
        id
    }

    fn push_binary(
        builder: &mut ECodeBuilder,
        opcode: ECodeOpcode,
        left: IlValueId,
        right: IlValueId,
    ) -> IlValueId {
        emit_value(builder, ECodeOpSpec::new(opcode, 64), [left, right]).unwrap()
    }

    fn push_memory(builder: &mut ECodeBuilder, space: AddressSpaceId) -> IlValueId {
        let id = emit_value(builder, ECodeOpSpec::new(ECodeOpcode::Undefined, 0), []).unwrap();
        builder
            .emitter()
            .set_value_domain(id, ECodeDomain::Memory(space))
            .unwrap();
        id
    }

    fn push_wide_constant(builder: &mut ECodeBuilder, width: u32) -> IlValueId {
        emit_value(
            builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, width).with_immediate(0),
            [],
        )
        .unwrap()
    }

    fn push_store(
        builder: &mut ECodeBuilder,
        space: AddressSpaceId,
        address: IlValueId,
        value: IlValueId,
        memory: IlValueId,
    ) -> IlOpId {
        builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Store, 0).with_address_space(space),
                [address, value, memory],
                0,
            )
            .map(|(operation, _)| operation)
            .unwrap()
    }

    #[test]
    fn stack_object_width_rejects_an_unrepresentable_range() {
        let object = MCodeStackObject::new(i64::MIN, i64::MAX, false);

        assert_eq!(object.width(), None);
    }

    #[test]
    fn stack_pointer_offsets_propagate_through_frame_arithmetic() {
        let mut builder = builder();
        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let frame_size = push_constant(&mut builder, 0x20);
        let frame = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, frame_size);
        let local_offset = push_constant(&mut builder, 8);
        let local = push_binary(&mut builder, ECodeOpcode::Add, frame, local_offset);

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        assert_eq!(model.offset_of(stack_pointer), Some(0));
        assert_eq!(model.offset_of(frame), Some(-0x20));
        assert_eq!(model.offset_of(local), Some(-0x18));
    }

    #[test]
    fn stack_pointer_offsets_propagate_through_register_definitions() {
        let mut builder = builder();
        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let frame_size = push_constant(&mut builder, 0x20);
        let frame = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, frame_size);
        let written = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::WriteRegister, 64).with_immediate(STACK_POINTER),
            [frame],
        )
        .unwrap();
        builder
            .emitter()
            .set_value_domain(
                written,
                ECodeDomain::Register(RegisterId::new(STACK_POINTER)),
            )
            .unwrap();

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        assert_eq!(model.offset_of(written), Some(-0x20));
    }

    #[test]
    fn values_unrelated_to_the_stack_pointer_have_no_offset() {
        let mut builder = builder();
        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let left = push_constant(&mut builder, 10);
        let right = push_constant(&mut builder, 5);
        let sum = push_binary(&mut builder, ECodeOpcode::Add, left, right);

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        assert_eq!(model.offset_of(stack_pointer), Some(0));
        assert_eq!(model.offset_of(sum), None);
    }

    #[test]
    fn a_stack_pointer_redefined_after_a_clobber_is_unknown() {
        let mut builder = builder();
        let entry = push_entry_stack_pointer(&mut builder);
        let clobber = push_entry_stack_pointer(&mut builder);

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        assert_eq!(model.offset_of(entry), Some(0));
        assert_eq!(model.offset_of(clobber), None);
    }

    #[test]
    fn subtracting_i64_min_from_the_stack_pointer_is_unknown() {
        let mut builder = builder();
        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let huge = push_constant(&mut builder, u64::from_ne_bytes(i64::MIN.to_ne_bytes()));
        let frame = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, huge);

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        assert_eq!(model.offset_of(frame), None);
    }

    #[test]
    fn conflicting_phi_inputs_are_unknown() {
        let block = |index| IlBlockId::try_from_index(index).unwrap();
        let mut builder = builder();

        builder.set_graph(IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 5).unwrap(),
                    IlIndexRange::new(0, 2).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(2, 3).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(3, 4).unwrap(),
                    IlBlockProperties::empty(),
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![block(1), block(2), block(3), block(3)],
            vec![
                IlEdgeKinds::TAKEN,
                IlEdgeKinds::FALL_THROUGH,
                IlEdgeKinds::UNCONDITIONAL,
                IlEdgeKinds::UNCONDITIONAL,
            ],
        ));

        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let low = push_constant(&mut builder, 0x10);
        let near = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, low);
        let high = push_constant(&mut builder, 0x20);
        let far = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, high);

        let merged = builder.emitter().emit_block_arg(block(3), 64).unwrap();
        builder
            .emitter()
            .set_value_domain(
                merged,
                ECodeDomain::Register(RegisterId::new(STACK_POINTER)),
            )
            .unwrap();
        builder.emitter().emit_edge_args([]).unwrap();
        builder.emitter().emit_edge_args([]).unwrap();
        builder.emitter().emit_edge_args([near]).unwrap();
        builder.emitter().emit_edge_args([far]).unwrap();

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        assert_eq!(model.offset_of(near), Some(-0x10));
        assert_eq!(model.offset_of(far), Some(-0x20));
        assert_eq!(model.offset_of(merged), None);
    }

    #[test]
    fn a_stack_pointer_masked_for_alignment_becomes_unresolved() {
        let mut builder = builder();
        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let mask = push_constant(
            &mut builder,
            u64::from(u32::MAX) << 4 | 0xffff_ffff_0000_0000,
        );
        let aligned = push_binary(&mut builder, ECodeOpcode::And, stack_pointer, mask);

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        assert_eq!(model.offset_of(aligned), None);
    }

    #[test]
    fn a_fixed_slot_store_maps_to_a_stack_object() {
        let mut builder = builder();
        let space = AddressSpaceId::new(0);
        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let size = push_constant(&mut builder, 0x20);
        let frame = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, size);
        let field = push_constant(&mut builder, 8);
        let address = push_binary(&mut builder, ECodeOpcode::Add, frame, field);
        let value = push_constant(&mut builder, 0xdead);
        let memory = push_memory(&mut builder, space);
        let store = push_store(&mut builder, space, address, value, memory);

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        let access = model.access_for(store).expect("store is a stack access");
        let object = model.objects()[access.object().index()];
        assert_eq!(object.start(), -0x18);
        assert_eq!(object.width(), Some(64));
        assert_eq!(access.field_offset(), 0);
        assert!(!object.address_taken());
    }

    #[test]
    fn a_field_offset_within_a_merged_object_is_measured_in_bits() {
        let mut builder = builder();
        let space = AddressSpaceId::new(0);
        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let size = push_constant(&mut builder, 0x20);
        let frame = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, size);
        let wide_value = push_wide_constant(&mut builder, 128);
        let memory = push_memory(&mut builder, space);
        push_store(&mut builder, space, frame, wide_value, memory);

        let field = push_constant(&mut builder, 8);
        let inner = push_binary(&mut builder, ECodeOpcode::Add, frame, field);
        let value = push_wide_constant(&mut builder, 64);
        let inner_store = push_store(&mut builder, space, inner, value, memory);

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        let access = model
            .access_for(inner_store)
            .expect("inner store is a stack access");
        let object = model.objects()[access.object().index()];
        assert_eq!(object.start(), -0x20);
        assert_eq!(object.width(), Some(128));
        assert_eq!(access.field_offset(), 64);
    }

    #[test]
    fn many_disjoint_slots_form_one_object_each() {
        let mut builder = builder();
        let space = AddressSpaceId::new(0);
        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let memory = push_memory(&mut builder, space);

        let count = 256;
        let mut sites = Vec::with_capacity(count);
        for slot in 1..=count {
            let size = push_constant(
                &mut builder,
                u64::try_from(slot).expect("slot is representable") * 8,
            );
            let address = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, size);
            let value = push_wide_constant(&mut builder, 64);
            sites.push(push_store(&mut builder, space, address, value, memory));
        }

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        assert_eq!(model.objects().len(), count);
        for site in sites {
            let access = model
                .access_for(site)
                .expect("slot store is a stack access");
            assert_eq!(access.field_offset(), 0);
        }
    }

    #[test]
    fn an_escaping_address_marks_its_object_taken() {
        let mut builder = builder();
        let stack_pointer = push_entry_stack_pointer(&mut builder);
        let size = push_constant(&mut builder, 0x20);
        let frame = push_binary(&mut builder, ECodeOpcode::Sub, stack_pointer, size);
        push_binary(&mut builder, ECodeOpcode::Add, frame, stack_pointer);

        let ir = builder.build_unchecked();
        let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

        assert!(
            model
                .objects()
                .iter()
                .any(|object| object.address_taken() && object.start() == -0x20)
        );
    }
}
