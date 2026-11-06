use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fugue_core::analysis::AnalysisError;
use fugue_core::engine::{
    Analyser, AnalyserProvider, AnalysisContext, AnalysisEngine, AnalysisEngineConfig,
};
use fugue_core::extension;
use fugue_core::loader::Loader;
use fugue_core::project::{ChangeKinds, Project};
use fugue_core::storage::TransientStorageProvider;
use fugue_core::types::AttributeMap;

const GLOBAL_ANALYSER_ATTRIBUTE: &str = "fugue.test.global-analyser";

static GLOBAL_CAUSE_OBSERVED: AtomicBool = AtomicBool::new(false);
static GLOBAL_RUNS: AtomicUsize = AtomicUsize::new(0);

struct GlobalAnalyser;

impl Analyser for GlobalAnalyser {
    fn name(&self) -> &'static str {
        "global-test"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::ADDRESS_SPACE_CREATED
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<bool>(GLOBAL_ANALYSER_ATTRIBUTE)
            .unwrap_or(false)
    }

    fn analyse(&mut self, context: &mut AnalysisContext<'_, '_>) -> Result<(), AnalysisError> {
        GLOBAL_RUNS.fetch_add(1, Ordering::SeqCst);
        GLOBAL_CAUSE_OBSERVED.store(
            context.regions().is_empty()
                && context.causes().iter().any(|cause| {
                    cause.kind() == ChangeKinds::ADDRESS_SPACE_CREATED && cause.range().is_none()
                }),
            Ordering::SeqCst,
        );
        Ok(())
    }
}

fn build_global_analyser(
    _project: &Project,
    _config: &AnalysisEngineConfig,
) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(GlobalAnalyser))
}

extension::submit! {
    AnalyserProvider::new::<GlobalAnalyser>("global-test", build_global_analyser)
}

#[test]
fn global_change_runs_declared_analyser() -> Result<(), Box<dyn Error>> {
    GLOBAL_CAUSE_OBSERVED.store(false, Ordering::SeqCst);
    GLOBAL_RUNS.store(0, Ordering::SeqCst);

    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(GLOBAL_ANALYSER_ATTRIBUTE, true);
    let project = Project::new_with_provider::<TransientStorageProvider>(&loader, attributes)?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    engine.create_space()?;
    engine.analyse()?;

    assert_eq!(GLOBAL_RUNS.load(Ordering::SeqCst), 1);
    assert!(GLOBAL_CAUSE_OBSERVED.load(Ordering::SeqCst));

    Ok(())
}
