use std::error::Error;

use fugue_core::engine::AnalysisEngine;
use fugue_core::il::common::{IlGraph, IlSourceSpan};
use fugue_core::il::pcode::{PCodeIr, PCodeLocation, PCodeLocationId, PCodeOp};
use fugue_core::ir::{
    Address, CodeBlockProperties, FlowTarget, FunctionProperties, Location, ProblemKind, Reference,
    ReferenceOrigin, SegmentProperties,
};
use fugue_core::lifter::ContextSet;
use fugue_core::project::{ChangeRecord, Project};
use fugue_core::queries::QueryReader;
use fugue_core::storage::{DEFAULT_SPACE_ID, SegmentMappingBuilder, TransientStorageProvider};
use fugue_core::types::Confidence;

mod common;

#[derive(Debug, PartialEq, Eq)]
struct BlockShape {
    address: Address,
    context: ContextSet,
    flows: Vec<FlowTarget>,
    properties: CodeBlockProperties,
}

#[derive(Debug, PartialEq, Eq)]
struct PCodeShape {
    graph: IlGraph,
    locations: Vec<PCodeLocation>,
    operands: Vec<PCodeLocationId>,
    operations: Vec<PCodeOp>,
    source_spans: Vec<IlSourceSpan>,
    targets: Vec<Location>,
}

impl From<&PCodeIr> for PCodeShape {
    fn from(pcode: &PCodeIr) -> Self {
        Self {
            graph: pcode.graph().clone(),
            locations: pcode.locations().to_vec(),
            operands: pcode.op_operands().to_vec(),
            operations: pcode.ops().to_vec(),
            source_spans: pcode.source_spans().to_vec(),
            targets: pcode.targets().to_vec(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FunctionShape {
    blocks: Vec<BlockShape>,
    callees: Vec<Address>,
    confidence: Confidence,
    origin: ReferenceOrigin,
    pcode: PCodeShape,
    properties: FunctionProperties,
    references: Vec<Reference>,
}

fn function_shape(
    reader: &QueryReader,
    entry: Address,
) -> Result<Option<FunctionShape>, Box<dyn Error>> {
    let project = reader.project()?;
    let Some(function) = project.functions().get_by_address(entry) else {
        return Ok(None);
    };
    let function_id = function.id();
    let blocks = function
        .blocks()
        .map(|(address, id)| {
            let block = project
                .blocks()
                .get_by_id(id)
                .ok_or("function block must exist")?;
            let mut properties = CodeBlockProperties::NONE;
            if block.is_call() {
                properties.insert(CodeBlockProperties::CALL);
            }
            if block.has_unresolved() {
                properties.insert(CodeBlockProperties::UNRESOLVED);
            }
            Ok(BlockShape {
                address,
                context: block.context().clone(),
                flows: block.flow_targets().collect(),
                properties,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let confidence = function.confidence();
    let origin = function.origin();
    let properties = function.properties();
    drop(project);
    let pcode = reader
        .pcode(function_id)?
        .ok_or("function PCode must exist")?;

    Ok(Some(FunctionShape {
        blocks,
        callees: reader.callees(entry).collect::<Result<Vec<_>, _>>()?,
        confidence,
        origin,
        pcode: PCodeShape::from(pcode.as_ref()),
        properties,
        references: reader
            .outgoing_references(entry)
            .collect::<Result<Vec<_>, _>>()?,
    }))
}

fn project_with_mutable_function(bytes: &[u8]) -> Result<(Project, Address), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let view = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.properties().is_writable() && view.size() >= bytes.len() as u64)
        .ok_or("fixture writable mapping missing")?;
    let mapping = project
        .segments()
        .mapping(view.mapping_ref().mapping_id())
        .ok_or("fixture mapping metadata missing")?;
    let entry = Address::in_default_space(0x7000_0000u64);
    let builder = SegmentMappingBuilder::new(
        entry,
        bytes.len() as u64,
        mapping.to_offset(view.start()),
        mapping.provider_id(),
    )
    .with_properties(
        SegmentProperties::PERM_READ
            | SegmentProperties::PERM_WRITE
            | SegmentProperties::PERM_EXECUTE,
    )
    .with_function_hints([entry.raw_address()]);

    {
        let mut transaction = project.transaction("test");
        let mapping = transaction.create_mapping(builder)?;
        transaction.add_mapping_to_space_top(DEFAULT_SPACE_ID, mapping)?;
        transaction.commit()?;
    }
    {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry, bytes)?;
        transaction.commit()?;
    }

    Ok((project, entry))
}

fn assert_byte_change_converges(
    original: &[u8],
    offset: u64,
    patch: &[u8],
    final_bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let (project, entry) = project_with_mutable_function(original)?;
    let incremental = AnalysisEngine::new(project)?;
    incremental.analyse()?;
    assert!(
        incremental.query_reader()?.function_id_at(entry)?.is_some(),
        "the mutable function hint must be recovered before invalidation"
    );

    let changes = incremental.write_bytes(entry + offset, patch)?;
    assert!(changes.records().iter().any(|record| {
        matches!(
            record,
            ChangeRecord::FunctionRemoved {
                entry: removed, ..
            } if *removed == entry
        )
    }));
    incremental.analyse()?;
    let incremental_reader = incremental.query_reader()?;
    let incremental_shape = function_shape(&incremental_reader, entry)?;

    let (project, clean_entry) = project_with_mutable_function(final_bytes)?;
    assert_eq!(clean_entry, entry);
    let clean = AnalysisEngine::new(project)?;
    clean.analyse()?;
    let clean_reader = clean.query_reader()?;
    let clean_shape = function_shape(&clean_reader, entry)?;

    assert!(clean_shape.is_some());
    assert_eq!(incremental_shape, clean_shape);

    Ok(())
}

#[test]
fn committed_functions_carry_discovery_confidence() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;

    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;
    let confidence = Confidence::somewhat_certain();

    let mut transaction = project.transaction("test");
    let id = transaction
        .add_function(common::one_block_function(entry, 8).with_confidence(confidence))?;
    transaction.commit()?;

    let function = project
        .functions()
        .get_by_id(id)
        .ok_or("function must exist")?;

    assert_eq!(
        function.confidence(),
        confidence,
        "the producer's confidence must survive commit, not be replaced by certain()"
    );

    Ok(())
}

#[test]
fn committed_functions_record_the_revision_they_read() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;

    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;
    let revision = project.revision();

    let mut transaction = project.transaction("test");
    let id = transaction.add_function(common::one_block_function(entry, 8))?;
    transaction.commit()?;

    let function = project
        .functions()
        .get_by_id(id)
        .ok_or("function must exist")?;

    assert_eq!(
        function.input_revision(),
        revision,
        "a derived fact must record the revision its producer read at"
    );

    Ok(())
}

#[test]
fn asserted_functions_are_distinguishable_from_derived() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;

    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;

    let mut transaction = project.transaction("test");
    let id = transaction.add_function(
        common::one_block_function(entry, 8).with_origin(ReferenceOrigin::Asserted),
    )?;
    transaction.commit()?;

    let function = project
        .functions()
        .get_by_id(id)
        .ok_or("function must exist")?;

    assert!(function.is_asserted());
    assert_eq!(function.origin(), ReferenceOrigin::Asserted);

    Ok(())
}

#[test]
fn byte_change_converges_with_clean_function_recovery() -> Result<(), Box<dyn Error>> {
    assert_byte_change_converges(&[0x55, 0xc3], 0, &[0xc3], &[0xc3, 0xc3])
}

#[test]
fn middle_byte_change_converges_with_clean_function_recovery() -> Result<(), Box<dyn Error>> {
    assert_byte_change_converges(&[0x55, 0x90, 0xc3], 1, &[0xc3], &[0x55, 0xc3, 0xc3])
}

#[test]
fn a_user_removed_function_is_not_rediscovered() -> Result<(), Box<dyn Error>> {
    let project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;

    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    assert!(
        reader.function_id_at(entry)?.is_some(),
        "recovery must find the entry point before it can be removed"
    );

    engine.remove_function(entry)?;
    engine.analyse()?;

    assert!(
        reader.function_id_at(entry)?.is_none(),
        "automatic analysis must not cross a user assertion and re-add the function"
    );

    let problem = reader
        .problem_at(entry, ProblemKind::HinderedByAssertedFact)?
        .ok_or("the barrier must be recorded as a problem")?;
    assert_eq!(problem.kind(), ProblemKind::HinderedByAssertedFact);

    Ok(())
}

#[test]
fn scheduler_retry_exhaustion_does_not_block_function_recovery() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;

    let mut transaction = project.transaction("test");
    transaction.add_problem(entry, ProblemKind::RetryBudgetExhausted)?;
    transaction.commit()?;

    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    assert!(
        engine.query_reader()?.function_id_at(entry)?.is_some(),
        "scheduler retry state must not become a semantic function-recovery blocker"
    );

    Ok(())
}
