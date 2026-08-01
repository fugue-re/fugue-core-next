use std::collections::BTreeMap;
use std::error::Error;

use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
use fugue_core::ir::{Address, CodeBlockId, FlowTarget, FunctionId, FunctionProperties, Insn};
use fugue_core::lifter::ContextSet;
use fugue_core::loader::Loader;
use fugue_core::project::Project;

#[derive(Debug, PartialEq, Eq)]
struct RecoveredBlock {
    address: Address,
    context: ContextSet,
    has_unresolved: bool,
    id: CodeBlockId,
    instructions: Vec<Insn>,
    is_call: bool,
    length: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct RecoveredFunction {
    blocks: Vec<RecoveredBlock>,
    entry_block: Option<CodeBlockId>,
    flow_targets: Vec<FlowTarget>,
    id: FunctionId,
    properties: FunctionProperties,
}

fn recover(
    loader: &Loader,
    worker_limit: usize,
) -> Result<BTreeMap<Address, RecoveredFunction>, Box<dyn Error>> {
    let project = Project::new_transient(loader)?;
    let config = AnalysisEngineConfig::default().with_worker_limit(worker_limit);
    let engine = AnalysisEngine::with_config(project, config)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let project = reader.project()?;
    let functions = project
        .functions()
        .iter()
        .map(|function| {
            let blocks = function
                .blocks()
                .filter_map(|(_, id)| project.blocks().get_by_id(id))
                .map(|block| RecoveredBlock {
                    address: block.address(),
                    context: block.context().clone(),
                    has_unresolved: block.has_unresolved(),
                    id: block.id(),
                    instructions: block.instructions().to_vec(),
                    is_call: block.is_call(),
                    length: block.len(),
                })
                .collect();
            let flow_targets = function.flow_targets(project.blocks()).collect();
            (
                function.address(),
                RecoveredFunction {
                    blocks,
                    entry_block: function.entry_block(),
                    flow_targets,
                    id: function.id(),
                    properties: function.properties(),
                },
            )
        })
        .collect();
    Ok(functions)
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
fn parallel_recovery_matches_serial_recovery() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/libipmi.so")?;
    let serial = recover(&loader, 1)?;
    let parallel = recover(&loader, 16)?;

    assert_eq!(
        parallel.keys().collect::<Vec<_>>(),
        serial.keys().collect::<Vec<_>>(),
    );
    for (address, parallel) in parallel {
        assert_eq!(
            parallel, serial[&address],
            "parallel recovery differs at {address}",
        );
    }
    Ok(())
}
