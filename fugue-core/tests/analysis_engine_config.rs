use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fugue_core::analysis::AnalysisError;
use fugue_core::engine::{
    Analyser, AnalyserProvider, AnalysisContext, AnalysisEngine, AnalysisEngineConfig, EngineError,
};
use fugue_core::extension;
use fugue_core::il::common::{IlGraph, IlSourceSpan};
use fugue_core::il::pcode::{PCodeIr, PCodeLocation, PCodeLocationId, PCodeOp};
use fugue_core::ir::{
    Address, CodeBlockId, FlowTarget, FunctionId, FunctionProperties, Location, Problem, Reference,
    ReferenceKind, ReferenceOrigin, ReferenceProperties, ReferenceTarget,
};
use fugue_core::lifter::ContextSet;
use fugue_core::loader::Loader;
use fugue_core::project::{ChangeKinds, Project};
use fugue_core::storage::TransientStorageProvider;
use fugue_core::types::AttributeMap;

const ANALYSER_SELECTION_ATTRIBUTE: &str = "fugue.test.analyser-selection";
const FIRST_SELECTION_ANALYSER: &str = "selection-first";
const SECOND_SELECTION_ANALYSER: &str = "selection-second";

static FIRST_SELECTION_RUNS: AtomicUsize = AtomicUsize::new(0);
static SECOND_SELECTION_RUNS: AtomicUsize = AtomicUsize::new(0);

struct SelectionAnalyser {
    name: &'static str,
    runs: &'static AtomicUsize,
}

impl Analyser for SelectionAnalyser {
    fn name(&self) -> &'static str {
        self.name
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::SEGMENT_MAPPED
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<bool>(ANALYSER_SELECTION_ATTRIBUTE)
            .unwrap_or(false)
    }

    fn analyse(&mut self, _context: &mut AnalysisContext<'_, '_>) -> Result<(), AnalysisError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct UnregisteredAnalyser;

extension::submit! {
    AnalyserProvider::new::<SelectionAnalyser>(
        FIRST_SELECTION_ANALYSER,
        |_project| {
            Ok(Box::new(SelectionAnalyser {
                name: FIRST_SELECTION_ANALYSER,
                runs: &FIRST_SELECTION_RUNS,
            }))
        },
    )
}

extension::submit! {
    AnalyserProvider::new::<SelectionAnalyser>(
        SECOND_SELECTION_ANALYSER,
        |_project| {
            Ok(Box::new(SelectionAnalyser {
                name: SECOND_SELECTION_ANALYSER,
                runs: &SECOND_SELECTION_RUNS,
            }))
        },
    )
}

#[derive(Debug, PartialEq, Eq)]
struct PCodeShape {
    graph: IlGraph,
    locations: Vec<PCodeLocation>,
    operands: Vec<PCodeLocationId>,
    operations: Vec<PCodeOp>,
    source_spans: Vec<IlSourceSpan>,
    targets: Vec<Location>,
}

impl From<&PCodeIr> for PCodeShape {
    fn from(pcode: &PCodeIr) -> Self {
        Self {
            graph: pcode.graph().clone(),
            locations: pcode.locations().to_vec(),
            operands: pcode.op_operands().to_vec(),
            operations: pcode.ops().to_vec(),
            source_spans: pcode.source_spans().to_vec(),
            targets: pcode.targets().to_vec(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RecoveredBlock {
    address: Address,
    context: ContextSet,
    has_unresolved: bool,
    id: CodeBlockId,
    is_call: bool,
    size: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct RecoveredFunction {
    blocks: Vec<RecoveredBlock>,
    entry_block: Option<CodeBlockId>,
    flow_targets: Vec<FlowTarget>,
    id: FunctionId,
    pcode: PCodeShape,
    properties: FunctionProperties,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RecoveredReference {
    from: Address,
    kind: ReferenceKind,
    origin: ReferenceOrigin,
    properties: ReferenceProperties,
    target: ReferenceTarget,
}

impl From<Reference> for RecoveredReference {
    fn from(reference: Reference) -> Self {
        Self {
            from: reference.from(),
            kind: reference.kind(),
            origin: reference.origin(),
            properties: reference.properties(),
            target: reference.target(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RecoveredProject {
    functions: BTreeMap<Address, RecoveredFunction>,
    problems: Vec<Problem>,
    references: BTreeSet<RecoveredReference>,
}

fn recover(loader: &Loader, worker_limit: usize) -> Result<RecoveredProject, Box<dyn Error>> {
    let project = Project::new_transient(loader)?;
    let config = AnalysisEngineConfig::default().with_worker_limit(worker_limit);
    let engine = AnalysisEngine::with_config(project, config)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let function_ids = reader
        .project()?
        .functions()
        .iter()
        .map(|function| function.id())
        .collect::<Vec<_>>();
    let mut functions = BTreeMap::new();
    let mut reference_sources = BTreeSet::new();

    for function_id in function_ids {
        let pcode = reader
            .pcode(function_id)?
            .ok_or("recovered function PCode missing")?;
        let project = reader.project()?;
        let function = project
            .functions()
            .get_by_id(function_id)
            .ok_or("recovered function missing")?;
        let blocks = function
            .blocks()
            .filter_map(|(_, id)| project.blocks().get_by_id(id))
            .map(|block| RecoveredBlock {
                address: block.address(),
                context: block.context().clone(),
                has_unresolved: block.has_unresolved(),
                id: block.id(),
                is_call: block.is_call(),
                size: block.size(),
            })
            .collect();
        let flow_targets = function.flow_targets(project.blocks()).collect();
        reference_sources.extend(pcode.source_spans().iter().map(IlSourceSpan::address));
        functions.insert(
            function.entry(),
            RecoveredFunction {
                blocks,
                entry_block: function.entry_block(),
                flow_targets,
                id: function.id(),
                pcode: PCodeShape::from(pcode.as_ref()),
                properties: function.properties(),
            },
        );
    }

    let problems = reader
        .problems()
        .map(|problem| problem.map(|problem| problem.problem().clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut references = BTreeSet::new();
    for source in reference_sources {
        references.extend(
            reader
                .outgoing_references(source)
                .map(|reference| reference.map(RecoveredReference::from))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }

    Ok(RecoveredProject {
        functions,
        problems,
        references,
    })
}

fn selection_project() -> Result<Project, Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut attributes = AttributeMap::new();
    attributes.set_attr(ANALYSER_SELECTION_ATTRIBUTE, true);
    Ok(Project::new_with_provider::<TransientStorageProvider>(
        &loader, attributes,
    )?)
}

fn reset_selection_runs() {
    FIRST_SELECTION_RUNS.store(0, Ordering::SeqCst);
    SECOND_SELECTION_RUNS.store(0, Ordering::SeqCst);
}

#[test]
fn analysis_engine_is_serial_by_default() {
    assert_eq!(AnalysisEngineConfig::default().worker_limit(), 1);
}

#[test]
fn analysis_engine_worker_limit_is_configurable() {
    let mut config = AnalysisEngineConfig::default().with_worker_limit(16);
    assert_eq!(config.worker_limit(), 16);

    config.set_worker_limit(0);
    assert_eq!(config.worker_limit(), 1);
}

#[test]
fn analysis_engine_lifted_cache_budget_is_configurable() {
    let mut config = AnalysisEngineConfig::default().with_lifted_cache_bytes(8192);
    assert_eq!(config.lifted_cache_bytes(), 8192);

    config.set_lifted_cache_bytes(0);
    assert_eq!(config.lifted_cache_bytes(), 0);
}

#[test]
fn analyser_selection_resolves_name_before_type_before_default() -> Result<(), Box<dyn Error>> {
    reset_selection_runs();
    let mut config = AnalysisEngineConfig::default();
    config.disable_all_analysers();
    config.enable_analyser::<SelectionAnalyser>();
    config.disable_named_analyser(SECOND_SELECTION_ANALYSER);
    let engine = AnalysisEngine::with_config(selection_project()?, config)?;
    engine.analyse()?;

    assert_eq!(FIRST_SELECTION_RUNS.load(Ordering::SeqCst), 1);
    assert_eq!(SECOND_SELECTION_RUNS.load(Ordering::SeqCst), 0);

    reset_selection_runs();
    let mut config = AnalysisEngineConfig::default();
    config.disable_all_analysers();
    config.enable_named_analyser(SECOND_SELECTION_ANALYSER);
    let engine = AnalysisEngine::with_config(selection_project()?, config)?;
    engine.analyse()?;

    assert_eq!(FIRST_SELECTION_RUNS.load(Ordering::SeqCst), 0);
    assert_eq!(SECOND_SELECTION_RUNS.load(Ordering::SeqCst), 1);

    Ok(())
}

#[test]
fn analyser_selection_rejects_unregistered_identifiers() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut config = AnalysisEngineConfig::default();
    config.disable_analyser::<UnregisteredAnalyser>();
    assert!(matches!(
        AnalysisEngine::with_config(Project::new_transient(&loader)?, config),
        Err(EngineError::UnregisteredAnalyserType(_))
    ));

    let mut config = AnalysisEngineConfig::default();
    config.disable_named_analyser("unregistered-analyser");
    assert!(matches!(
        AnalysisEngine::with_config(Project::new_transient(&loader)?, config),
        Err(EngineError::UnregisteredAnalyserName(name)) if name == "unregistered-analyser"
    ));

    Ok(())
}

#[test]
fn zero_lifted_cache_budget_disables_retention_without_disabling_queries()
-> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project.entry_point().ok_or("fixture entry missing")?;
    let config = AnalysisEngineConfig::default().with_lifted_cache_bytes(0);
    let engine = AnalysisEngine::with_config(project, config)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let function = reader
        .function_at(entry)?
        .ok_or("fixture entry function missing")?;

    let first_pcode = reader.pcode(function)?.ok_or("PCode missing")?;
    let second_pcode = reader.pcode(function)?.ok_or("PCode missing")?;
    assert_eq!(first_pcode, second_pcode);
    assert!(!Arc::ptr_eq(&first_pcode, &second_pcode));

    Ok(())
}

#[test]
fn parallel_recovery_matches_serial_recovery() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/libipmi.so")?;
    let serial = recover(&loader, 1)?;

    for worker_limit in [2, 4, 8, 16] {
        let parallel = recover(&loader, worker_limit)?;
        if parallel.functions.keys().ne(serial.functions.keys()) {
            let missing = serial
                .functions
                .keys()
                .filter(|address| !parallel.functions.contains_key(address))
                .take(8)
                .collect::<Vec<_>>();
            let unexpected = parallel
                .functions
                .keys()
                .filter(|address| !serial.functions.contains_key(address))
                .take(8)
                .collect::<Vec<_>>();
            panic!(
                "recovered function addresses differ with worker limit {worker_limit}: \
                 serial={}, parallel={}, missing={missing:?}, unexpected={unexpected:?}",
                serial.functions.len(),
                parallel.functions.len(),
            );
        }
        for (address, parallel_function) in &parallel.functions {
            let serial_function = &serial.functions[address];
            assert_eq!(
                parallel_function.id, serial_function.id,
                "recovered function id differs at {address} with worker limit {worker_limit}",
            );
            assert_eq!(
                parallel_function.blocks, serial_function.blocks,
                "recovered blocks differ at {address} with worker limit {worker_limit}",
            );
            assert_eq!(
                parallel_function.entry_block, serial_function.entry_block,
                "recovered entry block differs at {address} with worker limit {worker_limit}",
            );
            assert_eq!(
                parallel_function.flow_targets, serial_function.flow_targets,
                "recovered flow targets differ at {address} with worker limit {worker_limit}",
            );
            assert_eq!(
                parallel_function.pcode, serial_function.pcode,
                "recovered PCode differs at {address} with worker limit {worker_limit}",
            );
            assert_eq!(
                parallel_function.properties, serial_function.properties,
                "recovered function properties differ at {address} with worker limit {worker_limit}",
            );
        }
        assert_eq!(
            parallel.problems, serial.problems,
            "recovered problems differ with worker limit {worker_limit}",
        );
        assert_eq!(
            parallel.references, serial.references,
            "recovered references differ with worker limit {worker_limit}",
        );
    }
    Ok(())
}
