#![cfg(feature = "sqlite")]

use std::error::Error;
use std::path::Path;
use std::{fs, io};

use fugue_core::engine::AnalysisEngine;
use fugue_core::ir::Address;
use fugue_core::project::Project;
use fugue_core::storage::{
    AddressSpaceKind, DEFAULT_SPACE_ID, DefaultPersistentSegmentStorage, PERSISTENT,
    PersistentStorageProvider, SegmentProperties, SqliteEntityStorage,
};
use fugue_core::types::{ATTRIBUTE_PROJECT_PATH, AttributeMap};
use object::{Object, ObjectSection};

type SqliteProjectProvider =
    PersistentStorageProvider<SqliteEntityStorage<PERSISTENT>, DefaultPersistentSegmentStorage>;

fn provider_directories(root: &Path) -> Result<usize, io::Error> {
    let mut pending = vec![root.to_path_buf()];
    let mut count = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("segment-"))
                {
                    count += 1;
                }
                pending.push(path);
            }
        }
    }
    Ok(count)
}

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

    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let created = engine.create_space()?.space();
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

#[test]
fn rejected_space_creation_is_not_persisted_on_drop() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("rejected-segments.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path);

    let mut project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let spaces_at_load = project.segments().spaces().count();

    {
        let mut transaction = project.transaction("test");
        transaction.create_space()?;
    }
    assert_eq!(project.segments().spaces().count(), spaces_at_load);
    drop(project);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert_eq!(reopened.segments().spaces().count(), spaces_at_load);

    Ok(())
}

#[test]
fn distant_segments_survive_reopen() -> Result<(), Box<dyn Error>> {
    let bytes = fs::read("tests/distant-segments.elf")?;
    let elf = object::File::parse(bytes.as_slice())?;
    let far = elf
        .section_by_name(".far")
        .expect("fixture must have a far section");
    let far_address = Address::in_default_space(far.address());
    let far_bytes = far.data()?;

    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("distant-segments.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path);

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/distant-segments.elf",
        attributes.clone(),
    )?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    let entry = project.entry_point().expect("fixture has an entry point");
    assert!(project.functions().get_by_address(entry).is_some());
    let mut read = vec![0u8; far_bytes.len()];
    project.segments().read_bytes(far_address, &mut read)?;
    assert_eq!(read, far_bytes);
    drop(project);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/distant-segments.elf",
        attributes,
    )?;
    let mut read = vec![0u8; far_bytes.len()];
    reopened.segments().read_bytes(far_address, &mut read)?;
    assert_eq!(read, far_bytes);

    Ok(())
}

#[test]
fn synthetic_mappings_survive_reopen() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(
        ATTRIBUTE_PROJECT_PATH,
        directory.path().join("synthetic.fdbz"),
    );

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let engine = AnalysisEngine::new(project)?;
    let space = engine
        .create_space_with(
            "synthetic",
            AddressSpaceKind::Overlay {
                base: DEFAULT_SPACE_ID,
            },
        )?
        .space();

    let blocks = [0x10usize, 0x100, 0x1000, 0x8000]
        .into_iter()
        .enumerate()
        .map(|(index, size)| {
            let start = Address::new(space, 0x10_0000u64 * (index as u64 + 1));
            let bytes = (0..size)
                .map(|offset| (offset % 251) as u8 ^ index as u8)
                .collect::<Vec<_>>();
            (start, bytes)
        })
        .collect::<Vec<_>>();
    for (start, bytes) in &blocks {
        engine.create_synthetic_mapping(*start, bytes.as_slice(), SegmentProperties::PERM_READ)?;
    }
    drop(engine.into_project()?);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    let reopened_space = reopened
        .segments()
        .address_space_by_name("synthetic")
        .expect("the named space must survive reopen");
    assert_eq!(reopened_space.id(), space);
    assert_eq!(
        reopened_space.kind(),
        AddressSpaceKind::Overlay {
            base: DEFAULT_SPACE_ID
        }
    );
    for (start, bytes) in &blocks {
        let mut read = vec![0u8; bytes.len()];
        reopened.segments().read_bytes_exact(*start, &mut read)?;
        assert_eq!(&read, bytes);
    }

    Ok(())
}

#[test]
fn rejected_synthetic_mapping_opens_no_provider() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(
        ATTRIBUTE_PROJECT_PATH,
        directory.path().join("rejected-synthetic.fdbz"),
    );

    let mut project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let providers = provider_directories(directory.path())?;

    {
        let mut transaction = project.transaction("test");
        let space = transaction.create_space_with("synthetic", AddressSpaceKind::Base)?;
        transaction.create_synthetic_mapping(
            Address::new(space, 0x1000u64),
            b"rejected",
            SegmentProperties::PERM_READ,
        )?;
    }
    assert_eq!(provider_directories(directory.path())?, providers);
    drop(project);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;
    assert!(
        reopened
            .segments()
            .address_space_by_name("synthetic")
            .is_none()
    );
    assert_eq!(provider_directories(directory.path())?, providers);

    Ok(())
}
