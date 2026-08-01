use super::*;

#[test]
#[ignore = "requires local language data and binary fixtures"]
fn project() -> Result<(), Box<dyn std::error::Error>> {
    with_logging(|| {
        let project = Project::from_file_transient("tests/ls.elf")?;

        let mut bytes = [0u8; 32];
        project.segments().read_bytes(0x4000u32, &mut bytes)?;

        assert_eq!(
            &bytes,
            &[
                0xF3, 0x0F, 0x1E, 0xFA, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x8B, 0x05, 0xB9, 0xEF, 0x01,
                0x00, 0x48, 0x85, 0xC0, 0x74, 0x02, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x08, 0xC3, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        Ok(())
    })
}

#[cfg(any(feature = "sqlite", feature = "rocksdb", feature = "mdbx"))]
#[test]
fn project_persistent_default() -> Result<(), Box<dyn std::error::Error>> {
    with_logging(|| {
        let directory = tempfile::tempdir()?;
        let project_path = directory.path().join("ls.fdbz");
        let project = Project::from_file_with_provider_and_attributes::<
            PersistentStorageProvider<
                DefaultPersistentEntityStorage,
                DefaultPersistentSegmentStorage,
            >,
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
            PersistentStorageProvider<
                DefaultPersistentEntityStorage,
                DefaultPersistentSegmentStorage,
            >,
        >(project_path)?;

        assert_eq!(project.platform(), &created);
        drop(project);

        Ok(())
    })
}

#[cfg(feature = "mdbx")]
#[test]
fn project_persistent_mdbx() -> Result<(), Box<dyn std::error::Error>> {
    with_logging(|| {
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
    })
}

#[cfg(feature = "rocksdb")]
#[test]
fn project_standalone() -> Result<(), Box<dyn std::error::Error>> {
    with_logging(|| {
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
    })
}
