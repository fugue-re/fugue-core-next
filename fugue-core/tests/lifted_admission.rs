use std::error::Error;

use fugue_core::engine::{AnalysisEngine, EngineError};
use fugue_core::il::common::{IlError, IlLevel};
use fugue_core::ir::FunctionId;
use fugue_core::loader::Loader;
use fugue_core::project::{Project, ProjectError};

#[test]
fn missing_parent_artefact_is_reported_before_admission() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let engine = AnalysisEngine::new(Project::new_transient(&loader)?)?;
    engine.analyse()?;

    assert!(matches!(
        engine.ensure_lifted(FunctionId::INVALID, IlLevel::ECode),
        Err(EngineError::Project(ProjectError::Il(
            IlError::MissingArtefact {
                level: IlLevel::PCode,
                ..
            }
        )))
    ));

    Ok(())
}
