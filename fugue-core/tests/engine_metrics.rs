use std::error::Error;

use fugue_core::engine::AnalysisEngine;
use fugue_core::project::Project;
use fugue_core::storage::TransientStorageProvider;

#[test]
fn analysis_records_dispatch_counters() -> Result<(), Box<dyn Error>> {
    let project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let metrics = engine.metrics();

    assert!(
        metrics.dispatches() > 0,
        "analysing a real binary must dispatch work"
    );
    assert!(
        metrics.items_dispatched() >= metrics.dispatches(),
        "each dispatch carries at least one work item"
    );

    Ok(())
}

#[test]
fn a_clean_run_reports_no_degradation() -> Result<(), Box<dyn Error>> {
    let project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let metrics = engine.metrics();

    assert_eq!(
        metrics.retries_exhausted(),
        0,
        "no work should exhaust its retry budget on a clean fixture"
    );
    Ok(())
}
