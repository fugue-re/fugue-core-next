#![cfg(feature = "static-lifters")]

use std::path::PathBuf;

use fugue_core::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
use fugue_core::engine::change::{ChangeRecord, FunctionChangeKind};
use fugue_core::ir::Address;
use fugue_core::lifter::ContextSet;
use fugue_core::project::Project;

struct Fixtures;

impl Fixtures {
    fn binary(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(name)
    }
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
    let changes = transaction.commit();

    assert!(changes.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping,
        space,
        range,
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
    let changes = transaction.commit();

    let new_range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should keep its placement after remap");

    assert!(changes.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping,
        space,
        range: old_range,
    }));
    assert!(changes.records().contains(&ChangeRecord::SegmentMapped {
        mapping,
        space,
        range: new_range,
    }));

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
    let changes = transaction.commit();

    assert_eq!(changes.records(), &[ChangeRecord::FunctionAdded { entry }]);
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
    let changes = transaction.commit();

    assert_eq!(
        changes.records(),
        &[ChangeRecord::FunctionChanged {
            entry,
            kind: FunctionChangeKind::Body
        }]
    );
    assert!(project.blocks().get_by_id(old_block).is_none());
    assert_eq!(project.blocks().len(), 1);

    Ok(())
}
