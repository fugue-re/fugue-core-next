use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

use fugue_core::analysis::AnalysisError;
use fugue_core::engine::change::ChangeKinds;
use fugue_core::engine::{
    Analyser, AnalyserProvider, AnalysisContext, AnalysisEngine, DEFAULT_WORK_ITEM_MAX_ATTEMPTS,
    ProjectUpdate, ProjectView,
};
use fugue_core::ir::{Address, AddressRange, AddressRangeSet, ProblemKind, ProblemScope};
use fugue_core::loader::Loader;
use fugue_core::project::Project;
use fugue_core::registry;
use fugue_core::storage::{SegmentMappingId, TransientStorageProvider};
use fugue_core::types::AttributeMap;

const ANALYSER_ATTRIBUTE: &str = "fugue.test.rejecting-collapse-analyser";
const WORK_ITEM_LIMIT: usize = 4096;

static ANALYSER_RUNS: AtomicUsize = AtomicUsize::new(0);

struct RejectingCollapseAnalyser;

impl Analyser for RejectingCollapseAnalyser {
    fn name(&self) -> &'static str {
        "rejecting-collapse-test"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::BYTES_WRITTEN
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<bool>(ANALYSER_ATTRIBUTE)
            .unwrap_or(false)
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        context: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = regions;
        let _ = context;
        ANALYSER_RUNS.fetch_add(1, Ordering::SeqCst);

        let missing = SegmentMappingId::try_from(u32::MAX as usize)
            .expect("u32 maximum must fit a segment mapping identifier");
        updates.push(ProjectUpdate::remove_mapping(missing));
        Ok(())
    }
}

fn build_rejecting_collapse_analyser(
    _project: &Project,
) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(RejectingCollapseAnalyser))
}

registry::submit! {
    AnalyserProvider::new(
        "rejecting-collapse-test",
        build_rejecting_collapse_analyser,
    )
}

#[test]
fn collapse_diagnostics_survive_rejected_admission() -> Result<(), Box<dyn Error>> {
    ANALYSER_RUNS.store(0, Ordering::SeqCst);

    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ANALYSER_ATTRIBUTE, true);
    let project = Project::new_with_provider::<TransientStorageProvider>(&loader, attributes)?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let first = Address::in_default_space(0x7000_0000u64);
    let mut regions = AddressRangeSet::new();
    for index in 0..=WORK_ITEM_LIMIT {
        regions.insert(
            first
                .checked_add((index as u64) * 2)
                .ok_or_else(|| io::Error::other("test work address overflow"))?,
        );
    }
    let last = first
        .checked_add((WORK_ITEM_LIMIT as u64) * 2)
        .ok_or_else(|| io::Error::other("test work extent overflow"))?;
    let expected_scope = ProblemScope::Range(AddressRange::new(
        first.space(),
        first.raw_address(),
        last.raw_address(),
    ));

    engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, regions)?;
    engine.analyse()?;

    assert_eq!(
        ANALYSER_RUNS.load(Ordering::SeqCst),
        DEFAULT_WORK_ITEM_MAX_ATTEMPTS,
        "the analyser admission must be rejected before diagnostics are flushed"
    );

    let mut causes_merged = false;
    let mut ranges_collapsed = false;
    for problem in engine.query_reader()?.problems() {
        let problem = problem?;
        match problem.kind() {
            ProblemKind::WorkCausesMerged => {
                assert_eq!(problem.scope(), expected_scope);
                causes_merged = true;
            }
            ProblemKind::PendingWorkCollapsed => {
                assert_eq!(problem.scope(), expected_scope);
                ranges_collapsed = true;
            }
            _ => {}
        }
    }

    assert!(causes_merged, "cause merging must be persisted");
    assert!(ranges_collapsed, "range collapse must be persisted");

    Ok(())
}
