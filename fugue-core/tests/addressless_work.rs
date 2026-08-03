use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fugue_core::analysis::AnalysisError;
use fugue_core::engine::change::ChangeKinds;
use fugue_core::engine::{
    Analyser, AnalyserProvider, AnalysisContext, AnalysisEngine, ProjectUpdate, ProjectView,
};
use fugue_core::extension;
use fugue_core::ir::AddressRangeSet;
use fugue_core::loader::Loader;
use fugue_core::project::Project;
use fugue_core::storage::TransientStorageProvider;
use fugue_core::types::AttributeMap;

const ADDRESSLESS_ANALYSER_ATTRIBUTE: &str = "fugue.test.addressless-analyser";

static ADDRESSLESS_CAUSE_OBSERVED: AtomicBool = AtomicBool::new(false);
static ADDRESSLESS_RUNS: AtomicUsize = AtomicUsize::new(0);

struct AddresslessAnalyser;

impl Analyser for AddresslessAnalyser {
    fn name(&self) -> &'static str {
        "addressless-test"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::SPACE_CREATED
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<bool>(ADDRESSLESS_ANALYSER_ATTRIBUTE)
            .unwrap_or(false)
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = updates;
        ADDRESSLESS_RUNS.fetch_add(1, Ordering::SeqCst);
        ADDRESSLESS_CAUSE_OBSERVED.store(
            regions.is_empty()
                && cx.causes().iter().any(|cause| {
                    cause.kind() == ChangeKinds::SPACE_CREATED && cause.range().is_none()
                }),
            Ordering::SeqCst,
        );
        Ok(())
    }
}

fn build_addressless_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(AddresslessAnalyser))
}

extension::submit! {
    AnalyserProvider::new("addressless-test", build_addressless_analyser)
}

#[test]
fn addressless_change_runs_declared_analyser() -> Result<(), Box<dyn Error>> {
    ADDRESSLESS_CAUSE_OBSERVED.store(false, Ordering::SeqCst);
    ADDRESSLESS_RUNS.store(0, Ordering::SeqCst);

    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ADDRESSLESS_ANALYSER_ATTRIBUTE, true);
    let project = Project::new_with_provider::<TransientStorageProvider>(&loader, attributes)?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    engine.create_space()?;
    engine.analyse()?;

    assert_eq!(ADDRESSLESS_RUNS.load(Ordering::SeqCst), 1);
    assert!(ADDRESSLESS_CAUSE_OBSERVED.load(Ordering::SeqCst));

    Ok(())
}
