use super::*;

#[test]
fn project_pcode_rejects_stale_input_revision() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let function = FunctionId::default();
    let stale_revision = project.semantic_revision();
    {
        let mut transaction = project.transaction("test");
        transaction.create_space()?;
        transaction.commit()?;
    }

    let ir = PCodeIr::new(
        IlMetadata::new(function, PCODE_SCHEMA_VERSION, stale_revision),
        IlGraph::default(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    project.storage.entities().insert(&function, &ir)?;

    assert!(matches!(
        project.pcode(function),
        Err(ProjectError::Il(IlError::StaleArtefact {
            level: IlLevel::PCode,
            ..
        }))
    ));

    Ok(())
}

#[test]
fn project_pcode_rejects_schema_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let project = Project::from_file_transient("tests/ls.elf")?;
    let function = FunctionId::default();
    let schema = IlSchemaVersion::new(PCODE_SCHEMA_VERSION.value() + 1);
    let ir = PCodeIr::new(
        IlMetadata::new(function, schema, project.semantic_revision()),
        IlGraph::default(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    project.storage.entities().insert(&function, &ir)?;

    assert!(matches!(
        project.pcode(function),
        Err(ProjectError::Il(IlError::SchemaMismatch {
            level: IlLevel::PCode,
            expected,
            found,
        })) if expected == PCODE_SCHEMA_VERSION.value() && found == schema.value()
    ));

    Ok(())
}
