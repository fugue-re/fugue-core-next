#![cfg(feature = "sqlite")]

use std::error::Error;

use fugue_core::engine::{AnalysisEngine, PersistencePolicy};
use fugue_core::project::Project;
use fugue_core::storage::{
    DefaultPersistentSegmentStorage, PERSISTENT, PersistentStorageProvider, SqliteEntityStorage,
};
use fugue_core::types::{ATTRIBUTE_PROJECT_PATH, AttributeMap};

type SqliteProjectProvider =
    PersistentStorageProvider<SqliteEntityStorage<PERSISTENT>, DefaultPersistentSegmentStorage>;

#[test]
fn created_space_survives_reopen() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("segments.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let spaces_at_load = project.segments().spaces().count();

    let engine = AnalysisEngine::with_policy(project, PersistencePolicy::OnIdle)?;
    engine.wait_until_idle()?;
    let created = engine.create_space()?.space();
    engine.save()?;
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;

    assert_eq!(
        reopened.segments().spaces().count(),
        spaces_at_load + 1,
        "space created after load must survive reopen"
    );
    assert!(
        reopened
            .segments()
            .spaces()
            .any(|space| space.id() == created),
        "the created space must be present after reopen"
    );

    Ok(())
}
