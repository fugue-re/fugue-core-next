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
        IlMetadata::new(function, stale_revision),
        IlGraph::default(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let mut stage = crate::il::storage::IlStage::default();
    stage.replace(&project.storage, ir)?;
    let writes = stage.prepare()?;
    project.storage.entities().apply_batch(&writes)?;

    assert!(matches!(
        project.pcode(function),
        Err(ProjectError::Il(IlError::StaleArtefact { ref form, .. })) if *form == PCodeIr::FORM
    ));

    Ok(())
}
