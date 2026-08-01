use std::io;
use std::path::PathBuf;

use fugue_core::engine::change::{ChangeKinds, ChangeRecord, FunctionChangeKind};
use fugue_core::ir::{
    Address, AddressRange, AddressRangeSet, FunctionProperties, IncompleteCodeBlock,
    IncompleteFunction, SymbolEntry, SymbolIndex, SymbolProperties, SymbolTableSelector,
};
use fugue_core::lifter::ContextSet;
use fugue_core::project::Project;
use fugue_core::storage::{DEFAULT_SPACE_ID, TransientStorageProvider};
use fugue_core::types::AttributeMap;

mod common;

use common::{one_block_function, writable_address};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name)
}

#[test]
fn test_loadable_fallback_preserves_caller_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let mut attributes = AttributeMap::new();
    attributes.set_attr("caller.custom", "preserved");
    attributes.set_attr("caller.other", 7u64);

    let project = Project::from_file_with_provider_and_attributes::<TransientStorageProvider>(
        fixture_path("ls.elf"),
        attributes,
    )?;

    assert_eq!(
        project
            .attributes()
            .get_attr::<String>("caller.custom")
            .as_deref(),
        Some("preserved")
    );
    assert_eq!(
        project.attributes().get_attr::<u64>("caller.other"),
        Some(7u64)
    );

    Ok(())
}

#[test]
fn repeated_function_replacement_publishes_one_change() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let entry = Address::from(0x7000_0000u64);
    let mut transaction = project.transaction("test");

    for _ in 0..=8192 {
        transaction.add_function(one_block_function(entry, 1))?;
    }
    let changes = transaction.commit()?;

    assert_eq!(changes.records().len(), 1);
    assert!(matches!(
        changes.records(),
        [ChangeRecord::FunctionAdded {
            entry: changed,
            ..
        }] if *changed == entry
    ));

    Ok(())
}

#[test]
fn test_removing_mapping_records_unmapped_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
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
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
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
fn test_rejecting_mapping_removal_preserves_placement() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
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
    drop(transaction);

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
fn test_rejecting_mapping_remap_preserves_old_range() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
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
    drop(transaction);

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
fn test_rejecting_space_creation_discards_space() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;

    let mut transaction = project.transaction("test");
    let space = transaction.create_space()?;
    drop(transaction);

    assert!(!project.segments().spaces().any(|s| s.id() == space));

    let mut transaction = project.transaction("test");
    let recreated = transaction.create_space()?;
    transaction.commit()?;

    assert_eq!(recreated, space);

    Ok(())
}

#[test]
fn test_rejecting_byte_write_restores_old_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let address = writable_address(&project, 1)?;
    let mut old = [0u8; 1];
    project.segments().read_bytes_exact(address, &mut old)?;
    let patch = [old[0] ^ 0xff];

    let mut transaction = project.transaction("test");
    transaction.write_bytes(address, &patch)?;
    let mut patched = [0u8; 1];
    transaction
        .project(ChangeKinds::all())
        .segments()
        .read_bytes_exact(address, &mut patched)?;
    assert_eq!(patched, patch);
    drop(transaction);

    let mut restored = [0u8; 1];
    project
        .segments()
        .read_bytes_exact(address, &mut restored)?;
    assert_eq!(restored, old);

    Ok(())
}

#[test]
fn test_partial_write_bytes_restores_before_error() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
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
        .project(ChangeKinds::all())
        .segments()
        .read_bytes_exact(address, &mut restored)?;
    assert_eq!(restored, old);
    drop(transaction);

    Ok(())
}

#[test]
fn test_adding_function_preserves_incomplete_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let entry = Address::from(0x4000u64);
    let mut function = IncompleteFunction::new_with(Some("named".into()), entry);
    function.mark_non_returning();
    function.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    let function_id = transaction.add_function(function)?;
    transaction.commit()?;

    let function = project
        .functions()
        .get_by_id(function_id)
        .expect("function should exist");
    assert_eq!(function.name().as_deref(), Some("named"));
    assert!(function.is_non_returning());
    let block_id = function
        .blocks()
        .next()
        .map(|(_, block)| block)
        .expect("function should have one block");
    assert!(project.blocks().get_by_id(block_id).is_some());
    assert!(function.is_entry_block(block_id));
    assert!(function.is_exit_block(block_id));

    Ok(())
}

#[test]
fn test_replacing_function_removes_old_blocks() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut first = IncompleteFunction::new(entry);
    first.push_block(IncompleteCodeBlock::new(
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

    let mut second = IncompleteFunction::new(entry);
    second.push_block(IncompleteCodeBlock::new(
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
fn test_setting_function_properties_records_a_property_change()
-> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut function = IncompleteFunction::new(entry);
    function.push_block(IncompleteCodeBlock::new(
        entry,
        2,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(function)?;
    transaction.commit()?;

    let mut transaction = project.transaction("test");
    assert!(transaction.set_function_properties(entry, FunctionProperties::NON_RETURNING)?);
    assert!(!transaction.set_function_properties(entry, FunctionProperties::NON_RETURNING)?);
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
            kind: FunctionChangeKind::Properties,
            coverage: covered,
        }]
    );
    assert!(
        project
            .functions()
            .get_by_address(entry)
            .expect("function should exist")
            .is_non_returning()
    );

    let mut transaction = project.transaction("test");
    transaction.set_function_properties(entry, FunctionProperties::empty())?;
    drop(transaction);

    assert!(
        project
            .functions()
            .get_by_address(entry)
            .expect("function should exist")
            .is_non_returning()
    );

    Ok(())
}

#[test]
fn test_setting_symbol_properties_records_a_symbol_change() -> Result<(), Box<dyn std::error::Error>>
{
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let (id, address, properties) = project
        .symbols()
        .iter()
        .find(|(_, entry)| entry.is_function())
        .map(|(id, entry)| (id, entry.address(), entry.properties()))
        .expect("ls.elf should have a function symbol");

    let mut transaction = project.transaction("test");
    assert!(transaction.set_symbol_properties(id, properties | SymbolProperties::NON_RETURNING)?);
    let changes = transaction.commit()?;

    assert!(matches!(
        changes.records(),
        [ChangeRecord::SymbolChanged { address: at, .. }] if *at == address
    ));
    assert!(
        project
            .symbols()
            .get_by_id(id)
            .expect("symbol should exist")
            .is_non_returning()
    );

    let mut transaction = project.transaction("test");
    transaction.set_symbol_properties(id, properties)?;
    drop(transaction);

    assert!(
        project
            .symbols()
            .get_by_id(id)
            .expect("symbol should exist")
            .is_non_returning()
    );

    Ok(())
}

#[test]
fn test_rejecting_function_replacement_preserves_previous_body()
-> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut first = IncompleteFunction::new(entry);
    first.push_block(IncompleteCodeBlock::new(
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

    let mut second = IncompleteFunction::new(entry);
    second.push_block(IncompleteCodeBlock::new(
        entry,
        2,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(second)?;
    drop(transaction);

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
fn test_rejecting_function_insertion_discards_new_body() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut function = IncompleteFunction::new(entry);
    function.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(function)?;
    drop(transaction);

    assert!(project.functions().get_by_address(entry).is_none());
    assert_eq!(project.blocks().len(), 0);

    Ok(())
}

#[test]
fn test_rejecting_function_insertion_releases_allocated_ids()
-> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut first = IncompleteFunction::new(entry);
    first.push_block(IncompleteCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    let rolled_back_function = transaction.add_function(first)?;
    let rolled_back_block = transaction
        .function_at(entry)?
        .and_then(|function| function.blocks().next().map(|(_, id)| id))
        .expect("function should have one block");
    drop(transaction);

    let mut second = IncompleteFunction::new(entry);
    second.push_block(IncompleteCodeBlock::new(
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
fn test_rejecting_symbol_insertion_discards_new_symbol() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let selector = SymbolTableSelector::new(253);
    let index = SymbolIndex::new(selector, 0);
    let entry = Address::from(0x4010u64);
    let symbol = SymbolEntry::new(entry, "rejected_new_symbol", SymbolProperties::FUNCTION);

    let mut transaction = project.transaction("test");
    let rolled_back_id = transaction.add_symbol(index, symbol.clone())?;
    drop(transaction);

    assert!(project.symbols().get_by_index(index).is_none());
    assert!(project.symbols().get_by_address(entry).next().is_none());

    let mut transaction = project.transaction("test");
    let committed_id = transaction.add_symbol(index, symbol)?;
    transaction.commit()?;

    assert_eq!(committed_id, rolled_back_id);

    Ok(())
}

#[test]
fn test_rejecting_symbol_replacement_preserves_old_index() -> Result<(), Box<dyn std::error::Error>>
{
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let index = SymbolIndex::new(SymbolTableSelector::new(253), 1);
    let old_entry = Address::from(0x4020u64);
    let new_entry = Address::from(0x4030u64);

    let mut transaction = project.transaction("test");
    let old_id = transaction.add_symbol(
        index,
        SymbolEntry::new(
            old_entry,
            "preserved_old_symbol",
            SymbolProperties::FUNCTION,
        ),
    )?;
    transaction.commit()?;

    let mut transaction = project.transaction("test");
    transaction.add_symbol(
        index,
        SymbolEntry::new(new_entry, "rejected_new_symbol", SymbolProperties::DATA),
    )?;
    drop(transaction);

    let (restored_id, restored) = project
        .symbols()
        .get_by_index(index)
        .expect("symbol index should be restored");
    assert_eq!(restored_id, old_id);
    assert_eq!(restored.address(), old_entry);
    assert_eq!(restored.symbol().as_str(), "preserved_old_symbol");
    assert!(project.symbols().get_by_address(new_entry).next().is_none());

    Ok(())
}

#[test]
fn test_rejecting_symbol_removal_preserves_symbol() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(fixture_path("ls.elf"))?;
    let index = SymbolIndex::new(SymbolTableSelector::new(253), 2);
    let entry = Address::from(0x4040u64);

    let mut transaction = project.transaction("test");
    let id = transaction.add_symbol(
        index,
        SymbolEntry::new(entry, "preserved_symbol", SymbolProperties::FUNCTION),
    )?;
    transaction.commit()?;

    let mut transaction = project.transaction("test");
    assert!(transaction.remove_symbol_by_index(index)?);
    drop(transaction);

    let (restored_id, restored) = project
        .symbols()
        .get_by_index(index)
        .expect("symbol index should be restored");
    assert_eq!(restored_id, id);
    assert_eq!(restored.address(), entry);
    assert_eq!(restored.symbol().as_str(), "preserved_symbol");

    Ok(())
}
