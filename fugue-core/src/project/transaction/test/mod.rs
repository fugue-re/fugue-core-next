use std::io;

use fugue_lifter::runtime::pcode::Inputs;

use super::*;
use crate::analysis::control::CancellationToken;
use crate::arch::Arch;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlDominance, IlError, IlGraph, IlIndexRange,
    IlMetadata, IlSourceSpan, IlValueId,
};
use crate::il::ecode::{
    ECodeBuilder, ECodeIr, ECodeLiveness, ECodeOpcode, ECodeUses, PCodeToECode,
};
use crate::il::mcode::{MCodeBuilder, MCodeIr};
use crate::il::pcode::{
    PCodeBuilder, PCodeIr, PCodeLifterSpaceHandle, PCodeLocation, PCodeLocationProperties,
    PCodeOpSpec, PCodeOpcode,
};
use crate::ir::{
    AddressRange, AddressRangeSet, AddressWithContext, IncompleteCodeBlock, IncompleteFunction,
    Insn, InsnEntry, InsnProperties, ProblemKind, Reference, ReferenceKind, ReferenceOrigin,
    ReferenceProperties, ReferenceTarget, Switch, SwitchCase, SwitchModel, SymbolEntry,
    SymbolIndex, SymbolProperties, SymbolTableSelector,
};
use crate::lifter::{ContextSet, Op, RawPCodeOp, Varnode, resolve_language};
use crate::project::FunctionChangeKind;
use crate::storage::segments::DEFAULT_SPACE_ID;
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::space::AddressSpaceId;

mod derived_references;
mod function_partition;
mod invalidation;
mod lifted;

fn pcode_reference_ir(
    function: FunctionId,
    source: Address,
    target_space: AddressSpaceId,
    target_offset: u64,
    opcode: PCodeOpcode,
) -> Result<PCodeIr, Box<dyn std::error::Error>> {
    let metadata = IlMetadata::new(function, 0);
    let mut builder = PCodeBuilder::new(metadata, IlGraph::default());

    builder.set_source_spans(vec![IlSourceSpan::new(
        IlIndexRange::new(0, 1)?,
        source,
        0,
        1,
    )]);

    let pointer = builder.emitter().intern_location(PCodeLocation::new(
        PCodeLifterSpaceHandle::new(0),
        target_offset,
        8,
        PCodeLocationProperties::CONSTANT,
    ))?;
    let value = builder.emitter().intern_location(PCodeLocation::new(
        PCodeLifterSpaceHandle::new(1),
        0,
        8,
        PCodeLocationProperties::REGISTER,
    ))?;
    let output = opcode.requires_output().then_some(value);
    match opcode {
        PCodeOpcode::Store => {
            builder.emitter().emit(
                PCodeOpSpec::new(opcode).with_address_space(target_space),
                output,
                [pointer, value],
            )?;
        }
        _ => {
            builder.emitter().emit(
                PCodeOpSpec::new(opcode).with_address_space(target_space),
                output,
                [pointer],
            )?;
        }
    }

    Ok(builder.build(&CancellationToken::default())?)
}

fn pcode_copy_ir(
    function: FunctionId,
    source: Address,
) -> Result<PCodeIr, Box<dyn std::error::Error>> {
    let metadata = IlMetadata::new(function, 0);
    let mut builder = PCodeBuilder::new(metadata, IlGraph::default());

    builder.set_source_spans(vec![IlSourceSpan::new(
        IlIndexRange::new(0, 1)?,
        source,
        0,
        1,
    )]);

    let location = builder.emitter().intern_location(PCodeLocation::new(
        PCodeLifterSpaceHandle::new(1),
        0,
        8,
        PCodeLocationProperties::REGISTER,
    ))?;
    builder.emitter().emit(
        PCodeOpSpec::new(PCodeOpcode::Copy),
        Some(location),
        [location],
    )?;

    Ok(builder.build(&CancellationToken::default())?)
}

fn lift_test_ecode(source: &PCodeIr) -> Result<ECodeIr, IlError> {
    let arch = Arch::new(resolve_language("x86:LE:64").expect("test language should resolve"));
    let platform = arch.platform();
    PCodeToECode::default().transform(source, &arch, &platform, &CancellationToken::default())
}

fn stage_pcode_with_references(
    transaction: &mut ProjectTransaction<'_>,
    pcode: PCodeIr,
) -> Result<(), ProjectError> {
    let mut coverage = AddressRangeSet::new();
    pcode.reference_coverage_into(&mut coverage);
    let references = pcode.data_references().collect::<Vec<_>>();
    transaction.replace_lifted(pcode)?;
    transaction.replace_derived_references(coverage, ReferenceKind::Data, references)?;
    Ok(())
}

fn flow_resolved_load_function(
    entry: Address,
    data_offset: u64,
) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
    let language = resolve_language("x86:LE:64")?;
    let operation = RawPCodeOp {
        op: Op::Load(language.default_space()),
        inputs: Inputs::one(Varnode::constant(data_offset, 8)),
        output: Varnode::new(language.register_space(), 0, 8),
    };
    let operations = [operation];
    let insn = Insn::from_resolved_flow(language, entry, 1, &operations)?;
    let mut function = IncompleteFunction::new(entry);

    let insn = match function.insn_entry(entry) {
        InsnEntry::Vacant(entry) => entry.insert(insn),
        InsnEntry::Occupied(_) => {
            return Err(io::Error::other("test instruction unexpectedly occupied").into());
        }
    };

    function.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        vec![insn],
        ContextSet::default(),
    ));

    Ok(function)
}

fn calling_function(
    entry: Address,
    callee: Address,
    size: usize,
) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
    let language = resolve_language("x86:LE:64")?;
    let operation = RawPCodeOp {
        op: Op::Call,
        inputs: Inputs::one(Varnode::new(language.default_space(), callee.offset(), 8)),
        output: Varnode::INVALID,
    };
    let operations = [operation];
    let insn = Insn::from_resolved_flow(language, entry, size, &operations)?;
    let mut function = IncompleteFunction::new(entry);

    let insn = match function.insn_entry(entry) {
        InsnEntry::Vacant(entry) => entry.insert(insn),
        InsnEntry::Occupied(_) => {
            return Err(io::Error::other("test instruction unexpectedly occupied").into());
        }
    };

    function.push_block(
        IncompleteCodeBlock::try_new(entry, size, vec![insn], ContextSet::default())
            .expect("test block size must be valid"),
    );

    Ok(function)
}

fn disassembled_function(
    entry: Address,
    size: usize,
) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
    let insn = Insn::from_disassembly(entry, size, InsnProperties::NEEDS_FLOW_RESOLUTION)?;
    let mut function = IncompleteFunction::new(entry);

    let insn = match function.insn_entry(entry) {
        InsnEntry::Vacant(entry) => entry.insert(insn),
        InsnEntry::Occupied(_) => {
            return Err(io::Error::other("test instruction unexpectedly occupied").into());
        }
    };

    function.push_block(
        IncompleteCodeBlock::try_new(entry, size, vec![insn], ContextSet::default())
            .expect("test block size must be valid"),
    );

    Ok(function)
}

fn writable_address(project: &Project) -> Result<Address, Box<dyn std::error::Error>> {
    project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.properties().is_writable())
        .map(|view| view.start())
        .ok_or_else(|| io::Error::other("fixture writable segment missing").into())
}

fn incomplete_function(entry: Address, len: usize) -> IncompleteFunction {
    let mut function = IncompleteFunction::new(entry);
    function.push_block(
        IncompleteCodeBlock::try_new(entry, len, Vec::new(), ContextSet::default())
            .expect("test block size must be valid"),
    );

    function
}

fn tagged_source_spans(payload: &[u8]) -> Vec<IlSourceSpan> {
    let tag = payload.first().copied().unwrap_or_default();
    vec![IlSourceSpan::new(
        IlIndexRange::EMPTY,
        Address::new(DEFAULT_SPACE_ID, u64::from(tag)),
        u32::from(tag),
        u32::try_from(payload.len()).expect("test payload size should fit"),
    )]
}

fn single_block_graph() -> IlGraph {
    IlGraph::new(
        vec![IlBlock::new(
            IlIndexRange::EMPTY,
            IlIndexRange::EMPTY,
            IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
        )],
        Vec::new(),
        Vec::new(),
    )
}

fn pcode_for_test(function: FunctionId, graph: IlGraph) -> PCodeIr {
    PCodeBuilder::new(IlMetadata::new(function, 0), graph)
        .build(&CancellationToken::default())
        .expect("test PCode IR should verify")
}

fn tagged_pcode(function: FunctionId, payload: &[u8]) -> PCodeIr {
    let mut builder = PCodeBuilder::new(IlMetadata::new(function, 0), IlGraph::default());
    builder.set_source_spans(tagged_source_spans(payload));
    builder
        .build(&CancellationToken::default())
        .expect("test PCode IR should verify")
}

fn ecode_for_test(function: FunctionId, graph: IlGraph) -> ECodeIr {
    ECodeBuilder::new(IlMetadata::new(function, 0), graph)
        .build(&CancellationToken::default())
        .expect("test ECode IR should verify")
}

fn mcode_for_test(function: FunctionId, graph: IlGraph) -> MCodeIr {
    MCodeBuilder::new(IlMetadata::new(function, 0), graph)
        .build(&CancellationToken::default())
        .expect("test MCode should verify")
}

fn first_mapping_placement(project: &Project) -> (AddressSpaceId, SegmentMappingId, AddressRange) {
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .next()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let range = project
        .segments()
        .mapping_placements(mapping)
        .find(|range| range.space() == space)
        .expect("mapping should have a placement in its priority space");

    (space, mapping, range)
}

#[test]
fn repeated_function_changes_keep_one_semantic_record() {
    let mut changes = ChangeStaging::default();
    let entry = Address::in_default_space(0x1000u64);
    let mut coverage = AddressRangeSet::new();
    coverage.insert(entry);

    for _ in 0..=MAX_DETAILED_CHANGE_RECORDS {
        changes.push(ChangeRecord::FunctionChanged {
            entry,
            kind: FunctionChangeKind::Body,
            coverage: coverage.clone(),
        });
    }

    assert!(!changes.collapsed);
    assert_eq!(changes.records().len(), 1);
    assert_eq!(
        changes.records(),
        [ChangeRecord::FunctionChanged {
            entry,
            kind: FunctionChangeKind::Body,
            coverage,
        }]
    );
}

#[test]
fn adding_then_removing_a_function_has_no_change() {
    let mut changes = ChangeStaging::default();
    let entry = Address::in_default_space(0x2000u64);
    let mut coverage = AddressRangeSet::new();
    coverage.insert(entry);

    changes.push(ChangeRecord::FunctionAdded {
        entry,
        coverage: coverage.clone(),
    });
    changes.push(ChangeRecord::FunctionRemoved { entry, coverage });

    assert!(changes.is_empty());
    assert!(!changes.semantic());
    assert!(changes.kinds().is_empty());
}

#[test]
fn removing_then_adding_a_function_has_only_the_net_change_kind() {
    let mut changes = ChangeStaging::default();
    let entry = Address::in_default_space(0x2000u64);
    let mut coverage = AddressRangeSet::new();
    coverage.insert(entry);

    changes.push(ChangeRecord::FunctionRemoved {
        entry,
        coverage: coverage.clone(),
    });
    changes.push(ChangeRecord::FunctionAdded {
        entry,
        coverage: coverage.clone(),
    });

    assert_eq!(changes.kinds(), ChangeKinds::FUNCTION_CHANGED);
    assert_eq!(
        changes.records(),
        [ChangeRecord::FunctionChanged {
            entry,
            kind: FunctionChangeKind::Body,
            coverage,
        }]
    );
}

#[test]
fn staged_change_detail_collapses_at_its_memory_bound() {
    let mut changes = ChangeStaging::default();

    for index in 0..=MAX_DETAILED_CHANGE_RECORDS {
        changes.push(ChangeRecord::FunctionAdded {
            entry: Address::in_default_space(index as u64),
            coverage: AddressRangeSet::new(),
        });
    }

    assert!(changes.collapsed);
    assert_eq!(changes.records().len(), 1);
    assert!(changes.semantic());
    assert!(changes.kinds().contains(ChangeKinds::FUNCTION_ADDED));

    let revision = Revision::new(7);
    let published = changes.finish(revision, ChangeSource::agent("test"));
    assert_eq!(
        published.records(),
        [ChangeRecord::Resynchronise { to: revision }]
    );
}
