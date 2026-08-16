use super::*;
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlGraph, IlIndexRange, IlMetadata, IlOpId,
    IlValueId,
};
use crate::il::ecode::test::emit_value;
use crate::il::ecode::{ECodeBuilder, ECodeOpSpec};
use crate::ir::FunctionId;
use crate::storage::segments::space::AddressSpaceId;

const STACK_POINTER: u64 = 0x20;

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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

    assert_eq!(model.offset_of(stack_pointer), Some(0));
    assert_eq!(model.offset_of(sum), None);
}

#[test]
fn a_stack_pointer_redefined_after_a_clobber_is_unknown() {
    let mut builder = builder();
    let entry = push_entry_stack_pointer(&mut builder);
    let clobber = push_entry_stack_pointer(&mut builder);

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
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

    let ir = builder
        .build_unchecked(&CancellationToken::default())
        .unwrap();
    let model = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);

    assert!(
        model
            .objects()
            .iter()
            .any(|object| object.address_taken() && object.start() == -0x20)
    );
}
