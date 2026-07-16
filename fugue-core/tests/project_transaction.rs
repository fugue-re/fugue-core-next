use std::io;
use std::path::PathBuf;

use fugue_core::analysis::control::CancellationToken;
use fugue_core::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
use fugue_core::engine::change::{ChangeRecord, FunctionChangeKind};
use fugue_core::il::common::{IlError, IlLevel};
use fugue_core::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, SymbolEntry, SymbolIndex, SymbolProperties,
    SymbolTableSelector,
};
use fugue_core::lifter::ContextSet;
use fugue_core::project::{Project, ProjectError};
use fugue_core::storage::segments::DEFAULT_SPACE_ID;
use fugue_core::types::AttributeMap;
use fugue_core::types::attributes::ATTRIBUTE_LOADER_FORMAT;

struct Fixtures;

impl Fixtures {
    fn binary(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(name)
    }
}

fn writable_address(project: &Project) -> Result<Address, Box<dyn std::error::Error>> {
    project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.properties().is_writable())
        .map(|view| view.start())
        .ok_or_else(|| io::Error::other("fixture writable segment missing").into())
}

fn cancelled_token() -> CancellationToken {
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    cancellation
}

fn partial_function(entry: Address, len: usize) -> PartialFunction {
    let mut function = PartialFunction::new(entry);
    function.push_block(PartialCodeBlock::new(
        entry,
        len,
        Vec::new(),
        ContextSet::default(),
    ));

    function
}

#[test]
fn test_loadable_fallback_preserves_caller_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let mut attributes = AttributeMap::new();
    attributes.set_attr("caller.custom", "preserved");
    attributes.set_attr(ATTRIBUTE_LOADER_FORMAT, "caller-format");

    let project = Project::from_file_transient_with(Fixtures::binary("ls.elf"), attributes)?;

    assert_eq!(
        project
            .attributes()
            .get_attr::<String>("caller.custom")
            .as_deref(),
        Some("preserved")
    );
    assert_eq!(
        project
            .attributes()
            .get_attr::<String>(ATTRIBUTE_LOADER_FORMAT)
            .as_deref(),
        Some("caller-format")
    );

    Ok(())
}

#[test]
fn test_ensure_lifted_rebuilds_deterministic_content() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = writable_address(&project)?;
    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 1))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        assert!(transaction.ensure_ecode_ssa(function, &CancellationToken::default())?);
        transaction.commit()?;
    }

    let first_pcode = project
        .pcode(function)?
        .expect("PCode IR should be present");
    let first_ecode = project.ecode(function)?.expect("LIR should be present");
    let first_ssa = project
        .ecode_ssa(function)?
        .expect("LIR SSA should be present");

    {
        let mut transaction = project.transaction("test");
        assert_eq!(transaction.remove_lifted_from(function, IlLevel::PCode)?, 3);
        transaction.commit()?;
    }

    {
        let mut transaction = project.transaction("test");
        assert!(transaction.ensure_ecode_ssa(function, &CancellationToken::default())?);
        transaction.commit()?;
    }

    assert_eq!(project.pcode(function)?, Some(first_pcode));
    assert_eq!(project.ecode(function)?, Some(first_ecode));
    assert_eq!(project.ecode_ssa(function)?, Some(first_ssa));

    Ok(())
}

#[test]
fn test_ensure_lifted_reports_missing_parent_artefact() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();

    let mut transaction = project.transaction("test");
    assert!(matches!(
        transaction.ensure_ecode(function, &CancellationToken::default()),
        Err(ProjectError::Il(IlError::MissingArtefact {
            level: IlLevel::PCode,
            ..
        }))
    ));
    transaction.rollback()?;

    Ok(())
}

#[test]
fn test_ensure_lifted_cancelled_materialises_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();
    let revision = project.semantic_revision();

    for level in [IlLevel::PCode, IlLevel::ECode, IlLevel::ECodeSsa] {
        let mut transaction = project.transaction("test");
        assert!(matches!(
            transaction.ensure_lifted(function, level, &cancelled_token()),
            Err(ProjectError::Il(IlError::Cancelled))
        ));
        transaction.rollback()?;
    }

    assert_eq!(project.semantic_revision(), revision);
    assert!(project.pcode(function)?.is_none());
    assert!(project.ecode(function)?.is_none());
    assert!(project.ecode_ssa(function)?.is_none());

    Ok(())
}

#[test]
fn test_removing_mapping_records_unmapped_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .first()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should have a placement in its priority space");

    let mut transaction = project.transaction("test");
    transaction.remove_mapping(mapping)?;
    let changes = transaction.commit()?;

    assert!(changes.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping,
        range: AddressRange::new(space, range.0, range.1),
    }));

    Ok(())
}

#[test]
fn test_remapping_mapping_records_old_and_new_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .first()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let old_range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should have a placement in its priority space");
    let new_start = project
        .segments()
        .mapping(mapping)
        .expect("mapping should exist")
        .start()
        + 0x1000000u64;

    let mut transaction = project.transaction("test");
    transaction.remap_mapping(mapping, new_start)?;
    let changes = transaction.commit()?;

    let new_range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should keep its placement after remap");

    assert!(changes.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping,
        range: AddressRange::new(space, old_range.0, old_range.1),
    }));
    assert!(changes.records().contains(&ChangeRecord::SegmentMapped {
        mapping,
        range: AddressRange::new(space, new_range.0, new_range.1),
    }));

    Ok(())
}

#[test]
fn test_removing_mapping_rollback_restores_placement() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .first()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let old_range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should have a placement in its priority space");

    let mut transaction = project.transaction("test");
    transaction.remove_mapping(mapping)?;
    transaction.rollback()?;

    assert_eq!(
        project
            .segments()
            .mapping_placements(mapping)
            .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range)),
        Some(old_range)
    );

    Ok(())
}

#[test]
fn test_remapping_mapping_rollback_restores_old_range() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .first()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let old_range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should have a placement in its priority space");
    let new_start = project
        .segments()
        .mapping(mapping)
        .expect("mapping should exist")
        .start()
        + 0x1000000u64;

    let mut transaction = project.transaction("test");
    transaction.remap_mapping(mapping, new_start)?;
    transaction.rollback()?;

    assert_eq!(
        project
            .segments()
            .mapping_placements(mapping)
            .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range)),
        Some(old_range)
    );

    Ok(())
}

#[test]
fn test_create_space_rollback_removes_space() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;

    let mut transaction = project.transaction("test");
    let space = transaction.create_space()?;
    transaction.rollback()?;

    assert!(!project.segments().spaces().any(|s| s.id() == space));

    let mut transaction = project.transaction("test");
    let recreated = transaction.create_space()?;
    transaction.commit()?;

    assert_eq!(recreated, space);

    Ok(())
}

#[test]
fn test_write_bytes_rollback_restores_old_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let address = writable_address(&project)?;
    let mut old = [0u8; 1];
    project.segments().read_bytes_exact(address, &mut old)?;
    let patch = [old[0] ^ 0xff];

    let mut transaction = project.transaction("test");
    transaction.write_bytes(address, &patch)?;
    let mut patched = [0u8; 1];
    transaction
        .project()
        .segments()
        .read_bytes_exact(address, &mut patched)?;
    assert_eq!(patched, patch);
    transaction.rollback()?;

    let mut restored = [0u8; 1];
    project
        .segments()
        .read_bytes_exact(address, &mut restored)?;
    assert_eq!(restored, old);

    Ok(())
}

#[test]
fn test_partial_write_bytes_restores_before_error() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let address = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .filter(|view| view.properties().is_writable())
        .max_by_key(|view| view.last())
        .map(|view| view.last())
        .ok_or_else(|| io::Error::other("fixture writable segment missing"))?;
    let mut old = [0u8; 1];
    project.segments().read_bytes_exact(address, &mut old)?;

    let mut transaction = project.transaction("test");
    assert!(
        transaction
            .write_bytes(address, &[old[0] ^ 0xff, 0xdd])
            .is_err()
    );
    let mut restored = [0u8; 1];
    transaction
        .project()
        .segments()
        .read_bytes_exact(address, &mut restored)?;
    assert_eq!(restored, old);
    transaction.rollback()?;

    Ok(())
}

#[test]
fn test_replacing_function_removes_old_blocks() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut first = PartialFunction::new(entry);
    first.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(first)?;
    let changes = transaction.commit()?;

    let mut covered = AddressRangeSet::new();
    covered.insert(entry);
    assert_eq!(
        changes.records(),
        &[ChangeRecord::FunctionAdded {
            entry,
            coverage: covered,
        }]
    );
    assert_eq!(project.blocks().len(), 1);

    let old_block = project
        .functions()
        .get_by_address(entry)
        .and_then(|function| function.blocks().next().map(|(_, id)| id))
        .expect("function should have one block");

    let mut second = PartialFunction::new(entry);
    second.push_block(PartialCodeBlock::new(
        entry,
        2,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(second)?;
    let changes = transaction.commit()?;

    let mut covered = AddressRangeSet::new();
    covered.insert_raw_range(
        entry.space(),
        entry.raw_address()..=(entry + 1u64).raw_address(),
    );
    assert_eq!(
        changes.records(),
        &[ChangeRecord::FunctionChanged {
            entry,
            kind: FunctionChangeKind::Body,
            coverage: covered,
        }]
    );
    assert!(project.blocks().get_by_id(old_block).is_none());
    assert_eq!(project.blocks().len(), 1);

    Ok(())
}

#[test]
fn test_function_rollback_restores_previous_body() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut first = PartialFunction::new(entry);
    first.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(first)?;
    transaction.commit()?;

    let old_block = project
        .functions()
        .get_by_address(entry)
        .and_then(|function| function.blocks().next().map(|(_, id)| id))
        .expect("function should have one block");

    let mut second = PartialFunction::new(entry);
    second.push_block(PartialCodeBlock::new(
        entry,
        2,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(second)?;
    transaction.rollback()?;

    let function = project
        .functions()
        .get_by_address(entry)
        .expect("function should be restored");
    let blocks = function.blocks().collect::<Vec<_>>();
    assert_eq!(blocks, vec![(entry, old_block)]);
    assert!(project.blocks().get_by_id(old_block).is_some());
    assert_eq!(project.blocks().len(), 1);

    Ok(())
}

#[test]
fn test_function_rollback_removes_new_body() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut function = PartialFunction::new(entry);
    function.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(function)?;
    transaction.rollback()?;

    assert!(project.functions().get_by_address(entry).is_none());
    assert_eq!(project.blocks().len(), 0);

    Ok(())
}

#[test]
fn test_function_rollback_restores_allocated_ids() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut first = PartialFunction::new(entry);
    first.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    let rolled_back_function = transaction.add_function(first)?;
    let rolled_back_block = transaction
        .project()
        .functions()
        .get_by_id(rolled_back_function)
        .and_then(|function| function.blocks().next().map(|(_, id)| id))
        .expect("function should have one block");
    transaction.rollback()?;

    let mut second = PartialFunction::new(entry);
    second.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    let committed_function = transaction.add_function(second)?;
    transaction.commit()?;
    let committed_block = project
        .functions()
        .get_by_id(committed_function)
        .and_then(|function| function.blocks().next().map(|(_, id)| id))
        .expect("function should have one block");

    assert_eq!(committed_function, rolled_back_function);
    assert_eq!(committed_block, rolled_back_block);

    Ok(())
}

#[test]
fn test_symbol_rollback_removes_new_symbol() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let selector = SymbolTableSelector::new(253);
    let index = SymbolIndex::new(selector, 0);
    let entry = Address::from(0x4010u64);
    let symbol = SymbolEntry::new(entry, "rollback_new_symbol", SymbolProperties::FUNCTION);

    let mut transaction = project.transaction("test");
    let rolled_back_id = transaction.insert_symbol(index, symbol.clone());
    transaction.rollback()?;

    assert!(project.symbols().get_by_index(index).is_none());
    assert!(project.symbols().get_by_address(entry).next().is_none());

    let mut transaction = project.transaction("test");
    let committed_id = transaction.insert_symbol(index, symbol);
    transaction.commit()?;

    assert_eq!(committed_id, rolled_back_id);

    Ok(())
}

#[test]
fn test_symbol_rollback_restores_replaced_index() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let index = SymbolIndex::new(SymbolTableSelector::new(253), 1);
    let old_entry = Address::from(0x4020u64);
    let new_entry = Address::from(0x4030u64);

    let mut transaction = project.transaction("test");
    let old_id = transaction.insert_symbol(
        index,
        SymbolEntry::new(old_entry, "rollback_old_symbol", SymbolProperties::FUNCTION),
    );
    transaction.commit()?;

    let mut transaction = project.transaction("test");
    transaction.insert_symbol(
        index,
        SymbolEntry::new(new_entry, "rollback_new_symbol", SymbolProperties::DATA),
    );
    transaction.rollback()?;

    let (restored_id, restored) = project
        .symbols()
        .get_by_index(index)
        .expect("symbol index should be restored");
    assert_eq!(restored_id, old_id);
    assert_eq!(restored.address(), old_entry);
    assert_eq!(restored.symbol().as_str(), "rollback_old_symbol");
    assert!(project.symbols().get_by_address(new_entry).next().is_none());

    Ok(())
}

#[test]
fn test_symbol_rollback_restores_removed_symbol() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let index = SymbolIndex::new(SymbolTableSelector::new(253), 2);
    let entry = Address::from(0x4040u64);

    let mut transaction = project.transaction("test");
    let id = transaction.insert_symbol(
        index,
        SymbolEntry::new(entry, "rollback_removed_symbol", SymbolProperties::FUNCTION),
    );
    transaction.commit()?;

    let mut transaction = project.transaction("test");
    assert!(transaction.remove_symbol_by_index(index));
    transaction.rollback()?;

    let (restored_id, restored) = project
        .symbols()
        .get_by_index(index)
        .expect("symbol index should be restored");
    assert_eq!(restored_id, id);
    assert_eq!(restored.address(), entry);
    assert_eq!(restored.symbol().as_str(), "rollback_removed_symbol");

    Ok(())
}
