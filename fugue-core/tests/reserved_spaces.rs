use std::error::Error;
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use fugue_core::analysis::AnalysisError;
use fugue_core::engine::{
    Analyser, AnalyserProvider, AnalysisContext, AnalysisEngine, AnalysisEngineConfig,
};
use fugue_core::extension;
use fugue_core::ir::{Address, AddressRangeSet, Reference, ReferenceProperties, ReferenceTarget};
use fugue_core::loader::Loader;
use fugue_core::project::{ChangeKinds, Project};
use fugue_core::storage::{AddressSpaceId, AddressSpaceKind, SegmentProperties};

const DISCARDED_ANALYSER: &str = "stack-strings-discarded";
const EMPTY_ANALYSER: &str = "stack-strings-empty";
const FIRST_ANALYSER: &str = "stack-strings-first";
const SECOND_ANALYSER: &str = "stack-strings-second";
const STACK_STRING: &[u8] = b"stack string";
const STACK_STRINGS: &str = "stack-strings";

static DISCARDED_RUNS: AtomicUsize = AtomicUsize::new(0);
static DISCARDED_SPACE: Mutex<Option<AddressSpaceId>> = Mutex::new(None);
static EMPTY_RUNS: AtomicUsize = AtomicUsize::new(0);
static SHARED_RUNS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
enum Outcome {
    Committed,
    Discarded,
    Empty,
}

struct StackStringAnalyser {
    name: &'static str,
    outcome: Outcome,
    runs: &'static AtomicUsize,
}

impl Analyser for StackStringAnalyser {
    fn name(&self) -> &'static str {
        self.name
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::BYTES_WRITTEN | ChangeKinds::SEGMENT_MAPPED
    }

    fn can_analyse(&self, _project: &Project) -> bool {
        true
    }

    fn analyse(&mut self, context: &mut AnalysisContext<'_, '_>) -> Result<(), AnalysisError> {
        let Some(site) = context.project.entry_point() else {
            return Ok(());
        };
        if !context.regions().contains(site) {
            return Ok(());
        }
        self.runs.fetch_add(1, Ordering::SeqCst);

        if matches!(self.outcome, Outcome::Empty) {
            return Ok(());
        }

        let space = match context
            .project
            .segments()
            .address_space_by_name(STACK_STRINGS)
        {
            Some(space) => space.id(),
            None => context.reserve_space(
                STACK_STRINGS,
                AddressSpaceKind::Overlay { base: site.space() },
            )?,
        };
        let start = Address::new(space, site.offset());

        if !context.project.segments().contains_mapping(start) {
            context.updates.create_synthetic_mapping(
                start,
                STACK_STRING,
                SegmentProperties::PERM_READ,
            );
            context
                .updates
                .add_reference(Reference::data(site, start, ReferenceProperties::READ));
        }

        if matches!(self.outcome, Outcome::Discarded) {
            *DISCARDED_SPACE
                .lock()
                .expect("discarded space lock must not be poisoned") = Some(space);
            return Err(AnalysisError::pass_failed(
                self.name,
                io::Error::other("result discarded"),
            ));
        }

        Ok(())
    }
}

extension::submit! {
    AnalyserProvider::new::<StackStringAnalyser>(
        DISCARDED_ANALYSER,
        |_project, _config| {
            Ok(Box::new(StackStringAnalyser {
                name: DISCARDED_ANALYSER,
                outcome: Outcome::Discarded,
                runs: &DISCARDED_RUNS,
            }))
        },
    )
}

extension::submit! {
    AnalyserProvider::new::<StackStringAnalyser>(
        EMPTY_ANALYSER,
        |_project, _config| {
            Ok(Box::new(StackStringAnalyser {
                name: EMPTY_ANALYSER,
                outcome: Outcome::Empty,
                runs: &EMPTY_RUNS,
            }))
        },
    )
}

extension::submit! {
    AnalyserProvider::new::<StackStringAnalyser>(
        FIRST_ANALYSER,
        |_project, _config| {
            Ok(Box::new(StackStringAnalyser {
                name: FIRST_ANALYSER,
                outcome: Outcome::Committed,
                runs: &SHARED_RUNS,
            }))
        },
    )
}

extension::submit! {
    AnalyserProvider::new::<StackStringAnalyser>(
        SECOND_ANALYSER,
        |_project, _config| {
            Ok(Box::new(StackStringAnalyser {
                name: SECOND_ANALYSER,
                outcome: Outcome::Committed,
                runs: &SHARED_RUNS,
            }))
        },
    )
}

fn engine_with(analysers: &[&'static str]) -> Result<AnalysisEngine, Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut config = AnalysisEngineConfig::default();
    config.disable_all_analysers();
    for analyser in analysers {
        config.enable_named_analyser(*analyser);
    }
    Ok(AnalysisEngine::with_config(
        Project::new_transient(&loader)?,
        config,
    )?)
}

#[test]
fn shared_reservation() -> Result<(), Box<dyn Error>> {
    let engine = engine_with(&[FIRST_ANALYSER, SECOND_ANALYSER])?;
    engine.analyse()?;
    assert_eq!(SHARED_RUNS.load(Ordering::SeqCst), 2);

    let site = engine
        .query_reader()?
        .project()?
        .entry_point()
        .expect("fixture has an entry point");
    let mut regions = AddressRangeSet::new();
    regions.insert(site);
    engine.schedule_ranges(ChangeKinds::BYTES_WRITTEN, regions)?;
    engine.analyse()?;
    assert_eq!(SHARED_RUNS.load(Ordering::SeqCst), 4);

    let project = engine.into_project()?;
    let segments = project.segments();
    let space = segments
        .address_space_by_name(STACK_STRINGS)
        .expect("analysis creates the space");
    assert_eq!(
        space.kind(),
        AddressSpaceKind::Overlay { base: site.space() }
    );
    assert_eq!(
        segments
            .spaces()
            .filter(|space| space.name() == Some(STACK_STRINGS))
            .count(),
        1
    );
    assert_eq!(space.iter().count(), 1);

    let start = Address::new(space.id(), site.offset());
    let target = ReferenceTarget::Address(start);
    let sources = project
        .references()
        .references_to(target..=target, None)?
        .map(|reference| reference.map(|reference| reference.from()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(sources, [site]);

    let mut read = [0u8; STACK_STRING.len()];
    segments.read_bytes_exact(start, &mut read)?;
    assert_eq!(read, STACK_STRING);

    Ok(())
}

#[test]
fn discarded_reservation() -> Result<(), Box<dyn Error>> {
    let engine = engine_with(&[DISCARDED_ANALYSER, EMPTY_ANALYSER])?;
    let spaces = engine
        .query_reader()?
        .project()?
        .segments()
        .spaces()
        .count();
    engine.analyse()?;
    assert!(DISCARDED_RUNS.load(Ordering::SeqCst) > 0);
    assert_eq!(EMPTY_RUNS.load(Ordering::SeqCst), 1);

    {
        let project = engine.query_reader()?.project()?;
        assert!(
            project
                .segments()
                .address_space_by_name(STACK_STRINGS)
                .is_none()
        );
        assert_eq!(project.segments().spaces().count(), spaces);
    }

    let reserved = DISCARDED_SPACE
        .lock()
        .expect("discarded space lock must not be poisoned")
        .expect("discarded analysis reserves a space");
    assert_eq!(engine.create_space()?.space(), reserved);

    Ok(())
}
