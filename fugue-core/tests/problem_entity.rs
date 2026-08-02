use std::error::Error;

use fugue_core::engine::change::ChangeRecord;
use fugue_core::ir::{Address, ProblemKind};
use fugue_core::project::Project;
use fugue_core::storage::TransientStorageProvider;
#[cfg(feature = "sqlite")]
use fugue_core::storage::{
    DefaultPersistentSegmentStorage, PERSISTENT, PersistentStorageProvider, SqliteEntityStorage,
};
#[cfg(feature = "sqlite")]
use fugue_core::types::{ATTRIBUTE_PROJECT_PATH, AttributeMap};

mod common;

#[cfg(feature = "sqlite")]
type SqliteProjectProvider =
    PersistentStorageProvider<SqliteEntityStorage<PERSISTENT>, DefaultPersistentSegmentStorage>;

fn transient_project() -> Result<Project, Box<dyn Error>> {
    Ok(Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?)
}

#[test]
fn recording_a_problem_emits_a_record() -> Result<(), Box<dyn Error>> {
    let mut project = transient_project()?;
    let address = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;

    let mut transaction = project.transaction("test");
    transaction.add_problem(address, ProblemKind::DecodeFailed)?;
    let changes = transaction.commit()?;

    assert!(
        changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::ProblemRecorded { .. }))
    );

    Ok(())
}

#[test]
#[cfg(feature = "sqlite")]
fn problem_survives_reopen_and_is_queryable() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("problems.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let mut project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let address = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;

    let mut transaction = project.transaction("test");
    transaction.add_problem(address, ProblemKind::SwitchUnresolved)?;
    transaction.add_problem(address, ProblemKind::WorkCausesMerged)?;
    transaction.commit()?;
    drop(project);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;

    let problem = reopened
        .problems()
        .get(address, ProblemKind::SwitchUnresolved)
        .ok_or("problem must survive reopen")?;

    assert_eq!(problem.kind(), ProblemKind::SwitchUnresolved);
    assert_eq!(problem.attempts(), 1);
    assert!(
        reopened
            .problems()
            .get(address, ProblemKind::WorkCausesMerged)
            .is_some(),
        "a second problem at the same address must survive index reconstruction"
    );

    Ok(())
}

#[test]
fn repeated_problems_accumulate_attempts() -> Result<(), Box<dyn Error>> {
    let mut project = transient_project()?;
    let address = Address::from(0x1000u64);

    for _ in 0..3 {
        let mut transaction = project.transaction("test");
        transaction.add_problem(address, ProblemKind::DecodeFailed)?;
        transaction.commit()?;
    }

    let problem = project
        .problems()
        .get(address, ProblemKind::DecodeFailed)
        .ok_or("problem must exist")?;
    assert_eq!(problem.attempts(), 3);
    assert_eq!(project.problems().len(), 1);

    Ok(())
}

#[test]
fn semantic_input_change_starts_a_fresh_attempt_budget() -> Result<(), Box<dyn Error>> {
    let mut project = transient_project()?;
    let address = Address::from(0x1400u64);

    for _ in 0..3 {
        let mut transaction = project.transaction("test");
        transaction.add_problem(address, ProblemKind::DecodeFailed)?;
        transaction.commit()?;
    }

    let mut transaction = project.transaction("test");
    transaction.add_function(common::one_block_function(address, 4))?;
    let changes = transaction.commit()?;

    assert!(
        project
            .problems()
            .get(address, ProblemKind::DecodeFailed)
            .is_none(),
        "a relevant input change must invalidate the previous failure generation"
    );
    assert!(
        changes.records().iter().any(|record| {
            matches!(
                record,
                ChangeRecord::ProblemResolved { scope, kind }
                    if scope.address() == Some(address) && *kind == ProblemKind::DecodeFailed
            )
        }),
        "semantic invalidation must publish the problem resolution"
    );

    let mut transaction = project.transaction("test");
    transaction.add_problem(address, ProblemKind::DecodeFailed)?;
    transaction.commit()?;

    assert_eq!(
        project
            .problems()
            .get(address, ProblemKind::DecodeFailed)
            .ok_or("problem must exist")?
            .attempts(),
        1
    );

    Ok(())
}

#[test]
fn unrelated_input_changes_do_not_reset_attempts() -> Result<(), Box<dyn Error>> {
    let mut project = transient_project()?;
    let address = Address::from(0x1400u64);

    for _ in 0..3 {
        let mut transaction = project.transaction("test");
        transaction.add_problem(address, ProblemKind::DecodeFailed)?;
        transaction.commit()?;
    }

    let mut transaction = project.transaction("test");
    transaction.add_function(common::one_block_function(Address::from(0x900000u64), 4))?;
    transaction.commit()?;

    let mut transaction = project.transaction("test");
    transaction.add_problem(address, ProblemKind::DecodeFailed)?;
    transaction.commit()?;

    assert_eq!(
        project
            .problems()
            .get(address, ProblemKind::DecodeFailed)
            .ok_or("problem must remain current")?
            .attempts(),
        4
    );

    Ok(())
}

#[test]
fn different_problem_kinds_at_one_address_remain_independent() -> Result<(), Box<dyn Error>> {
    let mut project = transient_project()?;
    let address = Address::from(0x1800u64);

    let mut transaction = project.transaction("test");
    transaction.add_problem(address, ProblemKind::DecodeFailed)?;
    transaction.add_problem(address, ProblemKind::WorkCausesMerged)?;
    transaction.commit()?;

    assert_eq!(project.problems().len(), 2);
    assert_eq!(
        project
            .problems()
            .get(address, ProblemKind::DecodeFailed)
            .ok_or("decode problem must exist")?
            .attempts(),
        1
    );
    assert_eq!(
        project
            .problems()
            .get(address, ProblemKind::WorkCausesMerged)
            .ok_or("work-cause problem must exist")?
            .attempts(),
        1
    );

    let mut transaction = project.transaction("test");
    transaction.add_problem(address, ProblemKind::DecodeFailed)?;
    transaction.commit()?;

    assert_eq!(
        project
            .problems()
            .get(address, ProblemKind::DecodeFailed)
            .ok_or("decode problem must exist")?
            .attempts(),
        2
    );
    assert_eq!(
        project
            .problems()
            .get(address, ProblemKind::WorkCausesMerged)
            .ok_or("work-cause problem must exist")?
            .attempts(),
        1,
        "recording a semantic failure must not consume an operational problem's attempts"
    );

    Ok(())
}

#[test]
fn rejecting_a_transaction_preserves_the_previous_problem_state() -> Result<(), Box<dyn Error>> {
    let mut project = transient_project()?;
    let address = Address::from(0x3000u64);

    let mut transaction = project.transaction("test");
    transaction.add_problem(address, ProblemKind::DecodeFailed)?;
    drop(transaction);

    assert!(
        project
            .problems()
            .get(address, ProblemKind::DecodeFailed)
            .is_none()
    );

    Ok(())
}
