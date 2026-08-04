use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::thread;

use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
use fugue_core::ir::{Address, CodeBlockId, FlowTarget, FunctionId, FunctionProperties, Insn};
use fugue_core::lifter::ContextSet;
use fugue_core::loader::Loader;
use fugue_core::project::Project;
use fugue_core::queries::QueryError;

#[derive(Debug, PartialEq, Eq)]
struct RecoveredBlock {
    address: Address,
    context: ContextSet,
    has_unresolved: bool,
    id: CodeBlockId,
    insns: Vec<Insn>,
    is_call: bool,
    size: usize,
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

    let mut reader = engine.query_reader()?;
    let project = reader.project()?;
    let functions = project
        .functions()
        .iter()
        .map(|function| -> Result<_, Box<dyn Error>> {
            let blocks = function
                .blocks()
                .filter_map(|(_, id)| project.blocks().get_by_id(id))
                .map(|block| -> Result<_, Box<dyn Error>> {
                    let insns = reader
                        .insns(block.id())?
                        .ok_or("recovered block insns missing")?;
                    Ok(RecoveredBlock {
                        address: block.address(),
                        context: block.context().clone(),
                        has_unresolved: block.has_unresolved(),
                        id: block.id(),
                        insns: insns.as_ref().clone(),
                        is_call: block.is_call(),
                        size: block.size(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let flow_targets = function.flow_targets(project.blocks()).collect();
            Ok((
                function.entry(),
                RecoveredFunction {
                    blocks,
                    entry_block: function.entry_block(),
                    flow_targets,
                    id: function.id(),
                    properties: function.properties(),
                },
            ))
        })
        .collect::<Result<_, _>>()?;
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
fn analysis_engine_cache_budgets_are_configurable() {
    let mut config = AnalysisEngineConfig::default()
        .with_insn_cache_bytes(4096)
        .with_lifted_cache_bytes(8192);
    assert_eq!(config.insn_cache_bytes(), 4096);
    assert_eq!(config.lifted_cache_bytes(), 8192);

    config.set_insn_cache_bytes(0);
    config.set_lifted_cache_bytes(0);
    assert_eq!(config.insn_cache_bytes(), 0);
    assert_eq!(config.lifted_cache_bytes(), 0);
}

#[test]
fn zero_cache_budgets_disable_retention_without_disabling_queries() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project.entry_point().ok_or("fixture entry missing")?;
    let config = AnalysisEngineConfig::default()
        .with_insn_cache_bytes(0)
        .with_lifted_cache_bytes(0);
    let engine = AnalysisEngine::with_config(project, config)?;
    engine.analyse()?;

    let mut reader = engine.query_reader()?;
    let function = reader
        .function_id_at(entry)?
        .ok_or("fixture entry function missing")?;
    let block = {
        let project = reader.project()?;
        project
            .functions()
            .get_by_id(function)
            .and_then(|function| function.blocks().next().map(|(_, block)| block))
            .ok_or("fixture entry block missing")?
    };

    let first_insns = reader.insns(block)?.ok_or("insns missing")?;
    let second_insns = reader.insns(block)?.ok_or("insns missing")?;
    assert_eq!(first_insns, second_insns);
    assert!(!Arc::ptr_eq(&first_insns, &second_insns));

    let first_pcode = reader.pcode(function)?.ok_or("PCode missing")?;
    let second_pcode = reader.pcode(function)?.ok_or("PCode missing")?;
    assert_eq!(first_pcode, second_pcode);
    assert!(!Arc::ptr_eq(&first_pcode, &second_pcode));

    Ok(())
}

#[test]
fn cloned_readers_decode_independently_in_parallel() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let config = AnalysisEngineConfig::default().with_insn_cache_bytes(0);
    let engine = AnalysisEngine::with_config(project, config)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let blocks = reader
        .project()?
        .blocks()
        .iter()
        .take(256)
        .map(|block| block.id())
        .collect::<Vec<_>>();

    let decoded = thread::scope(|scope| {
        let tasks = (0..4)
            .map(|_| {
                let blocks = &blocks;
                let mut reader = reader.clone();
                scope.spawn(move || {
                    blocks
                        .iter()
                        .map(|&block| Ok(reader.insns(block)?.map_or(0, |insns| insns.len())))
                        .collect::<Result<Vec<_>, QueryError>>()
                })
            })
            .collect::<Vec<_>>();

        tasks
            .into_iter()
            .map(|task| task.join().expect("query task must complete"))
            .collect::<Result<Vec<_>, _>>()
    })?;

    assert!(decoded.windows(2).all(|pair| pair[0] == pair[1]));

    Ok(())
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
