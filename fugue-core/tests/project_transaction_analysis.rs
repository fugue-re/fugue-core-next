mod common;

use common::{one_block_function, writable_address};
use fugue_core::engine::AnalysisEngine;
use fugue_core::il::common::{IlArtefact, IlGraph, IlMetadata};
use fugue_core::il::ecode::ECodeIr;
use fugue_core::il::pcode::PCodeBuilder;
use fugue_core::project::{ChangeRecord, Project};

#[test]
fn ensure_lifted_builds_ecode_from_pcode() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project, 1)?;
    let function = {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry, &[0x90])?;
        let function = transaction.add_function(one_block_function(entry, 1))?;
        transaction.commit()?;
        function
    };
    let body = PCodeBuilder::new(IlMetadata::new(function, 0), IlGraph::default())
        .build()
        .expect("test PCode IR should verify");

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(body)?;
        transaction.commit()?;
    }
    assert!(project.pcode(function)?.is_some());

    let engine = AnalysisEngine::new(project)?;
    let changes = engine.ensure_lifted(function, ECodeIr::FORM)?;
    let reader = engine.query_reader()?;
    assert!(reader.pcode(function)?.is_some());
    assert!(reader.ecode(function)?.is_some());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::LiftedMaterialised {
                function,
                form: ECodeIr::FORM,
            })
    );

    let changes = engine.ensure_lifted(function, ECodeIr::FORM)?;
    assert!(changes.records().is_empty());

    Ok(())
}
