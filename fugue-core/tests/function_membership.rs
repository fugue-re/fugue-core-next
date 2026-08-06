use std::error::Error;

#[cfg(feature = "sqlite")]
use fugue_core::attributes;
use fugue_core::ir::{Address, IncompleteCodeBlock, IncompleteFunction, ReferenceOrigin};
#[cfg(feature = "sqlite")]
use fugue_core::lifter::ContextUpdate;
use fugue_core::lifter::{ContextBitRange, ContextSet};
use fugue_core::project::Project;
use fugue_core::storage::TransientStorageProvider;
#[cfg(feature = "sqlite")]
use fugue_core::storage::{
    DefaultPersistentSegmentStorage, PERSISTENT, PersistentStorageProvider, SqliteEntityStorage,
};
#[cfg(feature = "sqlite")]
use fugue_core::types::ATTRIBUTE_PROJECT_PATH;

mod common;
use common::writable_address;

#[cfg(feature = "sqlite")]
type SqliteProjectProvider =
    PersistentStorageProvider<SqliteEntityStorage<PERSISTENT>, DefaultPersistentSegmentStorage>;

fn function_sharing_tail(entry: Address, tail: Address, len: usize) -> IncompleteFunction {
    let mut function = IncompleteFunction::new(entry);
    function.push_block(
        IncompleteCodeBlock::try_new(entry, len, Vec::new(), ContextSet::default())
            .expect("test block length must fit"),
    );
    function.push_block(
        IncompleteCodeBlock::try_new(tail, len, Vec::new(), ContextSet::default())
            .expect("test block length must fit"),
    );
    function
}

fn function_with_contextual_tail(
    entry: Address,
    tail: Address,
    context: ContextSet,
) -> IncompleteFunction {
    let mut function = IncompleteFunction::new(entry);
    function.push_block(
        IncompleteCodeBlock::try_new(entry, 4, Vec::new(), ContextSet::default())
            .expect("test block length must fit"),
    );
    function.push_block(
        IncompleteCodeBlock::try_new(tail, 4, Vec::new(), context)
            .expect("test block length must fit"),
    );
    function
}

#[test]
fn two_functions_sharing_a_tail_share_one_block() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;

    let first_entry = entry;
    let second_entry = entry + 0x40u64;
    let tail = entry + 0x80u64;

    let mut transaction = project.transaction("test");
    let first = transaction.add_function(function_sharing_tail(first_entry, tail, 8))?;
    let second = transaction.add_function(function_sharing_tail(second_entry, tail, 8))?;
    transaction.commit()?;

    let first_tail = project
        .functions()
        .get_by_id(first)
        .ok_or("first function must exist")?
        .blocks()
        .find(|(address, _)| *address == tail)
        .map(|(_, id)| id)
        .ok_or("first function must contain the tail")?;

    let second_tail = project
        .functions()
        .get_by_id(second)
        .ok_or("second function must exist")?
        .blocks()
        .find(|(address, _)| *address == tail)
        .map(|(_, id)| id)
        .ok_or("second function must contain the tail")?;

    assert_eq!(
        first_tail, second_tail,
        "a shared tail must be one block contained by two functions, not two clones"
    );

    assert!(project.blocks().get_by_id(first_tail).is_some());
    assert_eq!(
        project
            .functions()
            .get_by_block_id(first_tail)
            .iter()
            .collect::<Vec<_>>(),
        vec![first, second]
    );

    Ok(())
}

#[test]
fn removing_one_function_keeps_a_shared_block_alive() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;

    let first_entry = entry;
    let second_entry = entry + 0x40u64;
    let tail = entry + 0x80u64;

    let mut transaction = project.transaction("test");
    let first = transaction.add_function(function_sharing_tail(first_entry, tail, 8))?;
    let second = transaction.add_function(function_sharing_tail(second_entry, tail, 8))?;
    transaction.commit()?;

    let shared = project
        .functions()
        .get_by_id(second)
        .ok_or("second function must exist")?
        .blocks()
        .find(|(address, _)| *address == tail)
        .map(|(_, id)| id)
        .ok_or("second function must contain the tail")?;

    let mut transaction = project.transaction("test");
    transaction.remove_function_by_id(first, ReferenceOrigin::Derived)?;
    transaction.commit()?;

    assert!(
        project.blocks().get_by_id(shared).is_some(),
        "removing one function must not delete a block still contained by another function"
    );

    assert_eq!(
        project
            .functions()
            .get_by_block_id(shared)
            .iter()
            .collect::<Vec<_>>(),
        vec![second]
    );

    let mut transaction = project.transaction("test");
    transaction.remove_function_by_id(second, ReferenceOrigin::Derived)?;
    transaction.commit()?;

    assert!(
        project.blocks().get_by_id(shared).is_none(),
        "removing the final membership must delete the block"
    );

    Ok(())
}

#[test]
fn context_distinct_blocks_at_one_address_remain_distinct() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let base = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;
    let shared = base + 0x100u64;
    let bits = ContextBitRange::new(0, 0);

    let mut transaction = project.transaction("test");
    let first = transaction.add_function(function_with_contextual_tail(
        base,
        shared,
        ContextSet::single(bits, 0),
    ))?;
    let second = transaction.add_function(function_with_contextual_tail(
        base + 0x40u64,
        shared,
        ContextSet::single(bits, 1),
    ))?;
    transaction.commit()?;

    let blocks = project.blocks().get_by_address(shared).collect::<Vec<_>>();
    assert_eq!(blocks.len(), 2);
    assert_ne!(blocks[0].id(), blocks[1].id());
    assert_ne!(blocks[0].context(), blocks[1].context());

    let first_block = project
        .functions()
        .get_by_id(first)
        .ok_or("first function must exist")?
        .blocks_at(shared)
        .next()
        .ok_or("first function must contain its contextual tail")?;
    let second_block = project
        .functions()
        .get_by_id(second)
        .ok_or("second function must exist")?
        .blocks_at(shared)
        .next()
        .ok_or("second function must contain its contextual tail")?;
    assert_ne!(first_block, second_block);

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn context_distinct_blocks_survive_persistent_admission_and_reopen() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("function-membership.fdbz");
    let mut project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes![ATTRIBUTE_PROJECT_PATH => project_path.clone()],
    )?;
    let base = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;
    let shared = base + 0x100u64;
    let bits = ContextBitRange::new(0, 0);
    let mut first_context = ContextSet::single(bits, 0);
    first_context.insert(ContextUpdate::new(ContextBitRange::new(1, 1), 1));
    let second_context = ContextSet::single(bits, 1);

    let mut transaction = project.transaction("test");
    transaction.add_function(function_with_contextual_tail(
        base,
        shared,
        first_context.clone(),
    ))?;
    transaction.add_function(function_with_contextual_tail(
        base + 0x40u64,
        shared,
        second_context.clone(),
    ))?;
    transaction.commit()?;
    drop(project);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes![ATTRIBUTE_PROJECT_PATH => project_path],
    )?;
    let blocks = reopened.blocks().get_by_address(shared).collect::<Vec<_>>();

    assert_eq!(blocks.len(), 2);
    assert_ne!(blocks[0].id(), blocks[1].id());
    assert_ne!(blocks[0].context(), blocks[1].context());
    assert!(blocks.iter().any(|block| block.context() == &first_context));
    assert!(
        blocks
            .iter()
            .any(|block| block.context() == &second_context)
    );

    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn persistent_functions_added_separately_share_one_block() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("function-membership.fdbz");
    let mut project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes![ATTRIBUTE_PROJECT_PATH => project_path],
    )?;
    let first_entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;
    let second_entry = first_entry + 0x40u64;
    let tail = first_entry + 0x80u64;

    let mut transaction = project.transaction("test");
    let first = transaction.add_function(function_sharing_tail(first_entry, tail, 8))?;
    transaction.commit()?;
    let first_tail = project
        .functions()
        .get_by_id(first)
        .ok_or("first function must exist")?
        .blocks_at(tail)
        .next()
        .ok_or("first function must contain the tail")?;

    let mut transaction = project.transaction("test");
    let second = transaction.add_function(function_sharing_tail(second_entry, tail, 8))?;
    transaction.commit()?;
    let second_tail = project
        .functions()
        .get_by_id(second)
        .ok_or("second function must exist")?
        .blocks_at(tail)
        .next()
        .ok_or("second function must contain the tail")?;

    assert_eq!(first_tail, second_tail);
    assert_eq!(
        project
            .functions()
            .get_by_block_id(first_tail)
            .iter()
            .collect::<Vec<_>>(),
        vec![first, second]
    );

    Ok(())
}

#[test]
fn a_shared_block_can_be_entry_for_one_function_and_ordinary_for_another()
-> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let shared = project
        .entry_point()
        .ok_or("fixture must have an entry point")?
        + 0x100u64;
    let other = shared - 0x40u64;

    let mut transaction = project.transaction("test");
    let entry_function = transaction.add_function(common_one_block(shared, 4))?;
    let ordinary_function = transaction.add_function(function_sharing_tail(other, shared, 4))?;
    transaction.commit()?;

    let shared_block = project
        .functions()
        .get_by_id(entry_function)
        .ok_or("entry function must exist")?
        .entry_block()
        .ok_or("entry function must have an entry block")?;
    let ordinary = project
        .functions()
        .get_by_id(ordinary_function)
        .ok_or("ordinary function must exist")?;

    assert!(!ordinary.is_entry_block(shared_block));
    assert!(
        ordinary
            .blocks_at(shared)
            .any(|block| block == shared_block)
    );
    assert_eq!(
        project
            .functions()
            .get_by_block_id(shared_block)
            .iter()
            .collect::<Vec<_>>(),
        vec![entry_function, ordinary_function]
    );

    Ok(())
}

#[test]
fn splitting_a_function_moves_its_tail_to_a_new_function() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let entry = writable_address(&project, 0x100)?;
    let tail = entry + 0x80u64;

    let mut transaction = project.transaction("test");
    transaction.write_bytes(entry, &[0x90; 8])?;
    transaction.write_bytes(tail, &[0x90; 8])?;
    let mut original_function = function_sharing_tail(entry, tail, 8);
    original_function.mark_non_returning();
    let original = transaction.add_function(original_function)?;
    transaction.commit()?;

    let original_blocks = project
        .functions()
        .get_by_id(original)
        .ok_or("the original function must exist")?
        .blocks()
        .collect::<Vec<_>>();

    let mut transaction = project.transaction("test");
    let split = transaction
        .split_function(original, original_blocks[1].1)?
        .ok_or("the tail must be splittable")?;
    transaction.commit()?;

    let parent = project
        .functions()
        .get_by_id(original)
        .ok_or("the parent must survive")?;
    assert_eq!(parent.blocks().count(), 1);
    assert!(parent.blocks().all(|(address, _)| address == entry));
    assert!(!parent.is_non_returning());
    assert_eq!(parent.blocks().collect::<Vec<_>>(), original_blocks[..1]);

    let child = project
        .functions()
        .get_by_id(split)
        .ok_or("the split function must exist")?;
    assert_eq!(child.entry(), tail);
    assert_eq!(child.blocks().count(), 1);
    assert!(!child.is_non_returning());
    assert_eq!(child.blocks().collect::<Vec<_>>(), original_blocks[1..]);

    let block = child.blocks().next().map(|(_, id)| id).unwrap();
    assert_eq!(
        project.functions().get_by_block_id(block).len(),
        1,
        "membership must transfer, not copy"
    );

    Ok(())
}

#[test]
fn merging_absorbs_one_function_into_another() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let entry = writable_address(&project, 0x100)?;
    let other = entry + 0x40u64;

    let mut transaction = project.transaction("test");
    transaction.write_bytes(entry, &[0x90; 8])?;
    transaction.write_bytes(other, &[0x90; 8])?;
    let mut target_function = common_one_block(entry, 8);
    target_function.mark_non_returning();
    let target = transaction.add_function(target_function)?;
    let source = transaction.add_function(common_one_block(other, 8))?;
    transaction.commit()?;

    let mut transaction = project.transaction("test");
    assert!(transaction.merge_functions(target, source)?);
    transaction.commit()?;

    let merged = project
        .functions()
        .get_by_id(target)
        .ok_or("the merge target must survive")?;
    assert_eq!(merged.blocks().count(), 2);
    assert!(merged.blocks().any(|(address, _)| address == other));
    assert!(!merged.is_non_returning());

    assert!(
        project.functions().get_by_address(other).is_none(),
        "the absorbed function must no longer be a function in its own right"
    );

    Ok(())
}

fn common_one_block(entry: Address, len: usize) -> IncompleteFunction {
    let mut function = IncompleteFunction::new(entry);
    function.push_block(
        IncompleteCodeBlock::try_new(entry, len, Vec::new(), ContextSet::default())
            .expect("test block length must fit"),
    );
    function
}

#[test]
fn rejecting_one_function_replacement_keeps_a_shared_block_alive() -> Result<(), Box<dyn Error>> {
    let mut project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;

    let first_entry = entry;
    let second_entry = entry + 0x40u64;
    let tail = entry + 0x80u64;

    let mut transaction = project.transaction("test");
    transaction.add_function(function_sharing_tail(first_entry, tail, 8))?;
    let second = transaction.add_function(function_sharing_tail(second_entry, tail, 8))?;
    transaction.commit()?;

    let shared = project
        .functions()
        .get_by_id(second)
        .ok_or("second function must exist")?
        .blocks()
        .find(|(address, _)| *address == tail)
        .map(|(_, id)| id)
        .ok_or("second function must contain the tail")?;

    let mut transaction = project.transaction("test");
    transaction.add_function(function_sharing_tail(first_entry, tail, 8))?;
    drop(transaction);

    assert!(
        project.blocks().get_by_id(shared).is_some(),
        "rejecting one function replacement must preserve the other function's membership"
    );
    assert!(
        project
            .functions()
            .get_by_id(second)
            .is_some_and(|function| function.blocks().any(|(address, _)| address == tail)),
        "the surviving function must still contain the shared tail"
    );

    Ok(())
}
