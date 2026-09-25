#![cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]

use fugue_core::attributes;
use fugue_core::platform::Format;
use fugue_core::project::Project;
#[cfg(feature = "mdbx")]
use fugue_core::storage::MdbxEntityStorage;
#[cfg(feature = "rocksdb")]
use fugue_core::storage::RocksDbEntityStorage;
use fugue_core::storage::{
    DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage, PersistentStorageProvider,
};
use fugue_core::types::ATTRIBUTE_PROJECT_PATH;

#[test]
fn project_persistent_default() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("ls.fdbz");
    let project = Project::from_file_with_provider_and_attributes::<
        PersistentStorageProvider<DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage>,
    >(
        "tests/ls.elf",
        attributes![
            ATTRIBUTE_PROJECT_PATH => project_path.clone()
        ],
    )?;

    let created = project.platform().clone();
    assert_eq!(created.compiler_spec_id(), "gcc");
    assert_eq!(created.format(), Format::Elf);
    drop(project);

    let project = Project::from_file_with_provider::<
        PersistentStorageProvider<DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage>,
    >(project_path)?;

    assert_eq!(project.platform(), &created);
    Ok(())
}

#[cfg(feature = "mdbx")]
#[test]
fn project_persistent_mdbx() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("ls.mdbx.fdbz");
    let project = Project::from_file_with_provider_and_attributes::<
        PersistentStorageProvider<MdbxEntityStorage, DefaultPersistentSegmentStorage>,
    >(
        "tests/ls.elf",
        attributes![
            ATTRIBUTE_PROJECT_PATH => project_path.clone()
        ],
    )?;

    drop(project);

    let project = Project::from_file_with_provider_and_attributes::<
        PersistentStorageProvider<MdbxEntityStorage, DefaultPersistentSegmentStorage>,
    >(
        "tests/ls.elf",
        attributes![
            ATTRIBUTE_PROJECT_PATH => project_path
        ],
    )?;

    drop(project);
    Ok(())
}

#[cfg(feature = "rocksdb")]
#[test]
fn project_standalone() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("standalone.fdbz");
    let project = Project::from_file_with_provider_and_attributes::<
        PersistentStorageProvider<RocksDbEntityStorage, DefaultPersistentSegmentStorage>,
    >(
        "tests/ls.elf",
        attributes![
            ATTRIBUTE_PROJECT_PATH => project_path.clone()
        ],
    )?;

    drop(project);

    let project = Project::from_file_with_provider::<
        PersistentStorageProvider<RocksDbEntityStorage, DefaultPersistentSegmentStorage>,
    >(project_path)?;

    drop(project);
    Ok(())
}
