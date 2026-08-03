use std::error::Error;
#[cfg(feature = "sqlite")]
use std::io;
#[cfg(feature = "sqlite")]
use std::sync::Mutex;
#[cfg(feature = "sqlite")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "sqlite")]
use fugue_core::analysis::AnalysisError;
use fugue_core::engine::AnalysisPhase;
#[cfg(feature = "sqlite")]
use fugue_core::engine::change::ChangeKinds;
#[cfg(feature = "sqlite")]
use fugue_core::engine::{
    Analyser, AnalyserProvider, AnalysisContext, AnalysisEngine, ProjectUpdate, ProjectView,
};
#[cfg(feature = "sqlite")]
use fugue_core::extension;
#[cfg(feature = "sqlite")]
use fugue_core::ir::{AddressRange, AddressRangeSet, ProblemKind, ProblemScope};
use fugue_core::project::Project;
use fugue_core::storage::TransientStorageProvider;
#[cfg(feature = "sqlite")]
use fugue_core::storage::{
    DefaultPersistentSegmentStorage, PERSISTENT, PersistentStorageProvider, SqliteEntityStorage,
};
#[cfg(feature = "sqlite")]
use fugue_core::types::{ATTRIBUTE_PROJECT_PATH, AttributeMap};

#[cfg(feature = "sqlite")]
type SqliteProjectProvider =
    PersistentStorageProvider<SqliteEntityStorage<PERSISTENT>, DefaultPersistentSegmentStorage>;

#[cfg(feature = "sqlite")]
const ANALYSER_ATTRIBUTE: &str = "fugue.test.coverage-analyser";
#[cfg(feature = "sqlite")]
const NEW_ANALYSER_NAME: &str = "coverage-new-name";
#[cfg(feature = "sqlite")]
const OLD_ANALYSER_NAME: &str = "coverage-old-name";

#[cfg(feature = "sqlite")]
static NEW_ANALYSER_REGIONS: Mutex<Option<AddressRangeSet>> = Mutex::new(None);
#[cfg(feature = "sqlite")]
static NEW_ANALYSER_RUNS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "sqlite")]
static OLD_ANALYSER_RUNS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "sqlite")]
struct CoverageAnalyser {
    name: &'static str,
}

#[cfg(feature = "sqlite")]
impl CoverageAnalyser {
    fn new(name: &'static str) -> Self {
        Self { name }
    }
}

#[cfg(feature = "sqlite")]
impl Analyser for CoverageAnalyser {
    fn name(&self) -> &'static str {
        self.name
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::BYTES_WRITTEN
    }

    fn phase(&self) -> AnalysisPhase {
        AnalysisPhase::Identify
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<String>(ANALYSER_ATTRIBUTE)
            .as_deref()
            == Some(self.name)
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        context: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let _ = project;
        let _ = context;
        let _ = updates;

        if self.name == OLD_ANALYSER_NAME {
            OLD_ANALYSER_RUNS.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }

        NEW_ANALYSER_RUNS.fetch_add(1, Ordering::SeqCst);
        let mut observed = NEW_ANALYSER_REGIONS
            .lock()
            .expect("coverage analyser region lock must not be poisoned");
        match observed.as_mut() {
            Some(observed) => {
                for range in regions.ranges() {
                    observed.insert_range(range);
                }
            }
            None => *observed = Some(regions.clone()),
        }
        Ok(())
    }
}

#[cfg(feature = "sqlite")]
fn build_new_coverage_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(CoverageAnalyser::new(NEW_ANALYSER_NAME)))
}

#[cfg(feature = "sqlite")]
fn build_old_coverage_analyser(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
    Ok(Box::new(CoverageAnalyser::new(OLD_ANALYSER_NAME)))
}

#[cfg(feature = "sqlite")]
extension::submit! {
    AnalyserProvider::new(NEW_ANALYSER_NAME, build_new_coverage_analyser)
}

#[cfg(feature = "sqlite")]
extension::submit! {
    AnalyserProvider::new(OLD_ANALYSER_NAME, build_old_coverage_analyser)
}

#[test]
fn a_fresh_project_has_covered_nothing() -> Result<(), Box<dyn Error>> {
    let project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;

    for phase in AnalysisPhase::ALL {
        assert!(
            project.coverage().covered(phase).is_empty(),
            "{phase} must start uncovered so unanalysed is distinguishable from empty"
        );
    }

    Ok(())
}

#[test]
#[cfg(feature = "sqlite")]
fn coverage_survives_reopen() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("coverage.fdbz");
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes.clone(),
    )?;
    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;

    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        attributes,
    )?;

    let covered = reopened.coverage().covered(AnalysisPhase::Partition);
    assert!(
        !covered.is_empty(),
        "function recovery runs in the partition phase, so its coverage must be durable"
    );
    assert!(
        reopened
            .coverage()
            .is_covered(AnalysisPhase::Partition, entry),
        "the entry point was analysed, so it must be recorded as covered"
    );

    let engine = AnalysisEngine::new(reopened)?;
    engine.analyse()?;
    assert_eq!(
        engine.metrics().dispatches(),
        0,
        "covered startup hints must not dispatch recovery again"
    );

    Ok(())
}

#[test]
#[cfg(feature = "sqlite")]
fn renamed_analyser_reprocesses_persisted_coverage() -> Result<(), Box<dyn Error>> {
    OLD_ANALYSER_RUNS.store(0, Ordering::SeqCst);
    NEW_ANALYSER_RUNS.store(0, Ordering::SeqCst);
    *NEW_ANALYSER_REGIONS
        .lock()
        .map_err(|_| io::Error::other("coverage analyser region lock poisoned"))? = None;

    let directory = tempfile::tempdir()?;
    let project_path = directory.path().join("renamed-coverage.fdbz");
    let mut old_attributes = AttributeMap::new();
    old_attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());
    old_attributes.set_attr(ANALYSER_ATTRIBUTE, OLD_ANALYSER_NAME);

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        old_attributes,
    )?;
    let entry = project
        .entry_point()
        .ok_or("fixture must have an entry point")?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let mut regions = AddressRangeSet::new();
    regions.insert(entry);
    engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, regions.clone())?;
    engine.analyse()?;
    assert_eq!(OLD_ANALYSER_RUNS.load(Ordering::SeqCst), 1);
    drop(engine);

    let mut new_attributes = AttributeMap::new();
    new_attributes.set_attr(ATTRIBUTE_PROJECT_PATH, project_path.clone());
    new_attributes.set_attr(ANALYSER_ATTRIBUTE, NEW_ANALYSER_NAME);
    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        new_attributes.clone(),
    )?;
    let engine = AnalysisEngine::new(project)?;
    engine.cancel()?;
    drop(engine);
    assert_eq!(
        NEW_ANALYSER_RUNS.load(Ordering::SeqCst),
        0,
        "cancelling before dispatch must leave replacement coverage pending"
    );

    let project = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        new_attributes.clone(),
    )?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    assert_eq!(NEW_ANALYSER_RUNS.load(Ordering::SeqCst), 1);
    assert_eq!(
        *NEW_ANALYSER_REGIONS
            .lock()
            .map_err(|_| io::Error::other("coverage analyser region lock poisoned"))?,
        Some(regions)
    );

    let invalidation = engine
        .query_reader()?
        .problems()
        .find_map(|problem| match problem {
            Ok(problem) if problem.kind() == ProblemKind::AnalysisCoverageInvalidated => {
                Some(Ok(problem.scope()))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .transpose()?;
    assert_eq!(
        invalidation,
        Some(ProblemScope::Range(AddressRange::point(entry)))
    );
    drop(engine);

    let reopened = Project::from_file_with_provider_and_attributes::<SqliteProjectProvider>(
        "tests/ls.elf",
        new_attributes,
    )?;
    assert!(
        reopened
            .coverage()
            .is_covered(AnalysisPhase::Identify, entry),
        "replacement coverage must be durable"
    );

    Ok(())
}
