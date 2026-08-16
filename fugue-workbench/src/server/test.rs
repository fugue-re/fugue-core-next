use std::io;

use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
use fugue_core::loader::Loader;
use fugue_core::project::Project;

use super::*;

#[test]
fn mcode_endpoint_renders_a_real_function() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/../fugue-core/tests/ls.elf");
    let loader = Loader::from_file(fixture)?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry_point()
        .ok_or_else(|| io::Error::other("fixture entry point missing"))?;
    let config = AnalysisEngineConfig::default().with_worker_limit(1);
    let engine = AnalysisEngine::with_config(project, config)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let response = Snapshot::new(&reader).il(entry, MCodeIr::FORM.as_str())?;

    assert_eq!(response.form, MCodeIr::FORM.as_str());
    assert!(!response.lines.is_empty());

    Ok(())
}
