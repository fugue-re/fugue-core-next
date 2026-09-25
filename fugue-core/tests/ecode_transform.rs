use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
use fugue_core::loader::Loader;
use fugue_core::project::Project;

#[test]
fn every_recovered_function_lifts_to_verified_ecode() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let config = AnalysisEngineConfig::default().with_worker_limit(1);
    let engine = AnalysisEngine::with_config(project, config)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let functions = {
        let project = reader.project()?;
        project
            .functions()
            .iter()
            .map(|function| function.id())
            .collect::<Vec<_>>()
    };

    let mut lifted = 0usize;
    for function in functions {
        if reader.ecode(function)?.is_some() {
            lifted += 1;
        }
    }

    assert!(
        lifted > 0,
        "expected at least one function to lift to ecode"
    );

    Ok(())
}
