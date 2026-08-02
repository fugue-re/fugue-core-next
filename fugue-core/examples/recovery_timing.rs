use std::env;
use std::error::Error;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::Instant;

use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
use fugue_core::ir::{CodeBlock, FlowTarget};
use fugue_core::lifter::{ContextSet, ContextUpdate};
use fugue_core::loader::Loader;
use fugue_core::project::Project;
use tracing_subscriber::EnvFilter;

#[derive(Default)]
struct ProjectCounts {
    functions: usize,
    blocks: usize,
    memberships: usize,
    flow_blocks: usize,
    flow_targets: usize,
    flow_with_fall_through: usize,
    blocks_with_context: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    if env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
    }

    let worker_limit = env::args()
        .nth(1)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1);
    let runs = env::args()
        .nth(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(8);
    let input = env::args()
        .nth(3)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/libipmi.so"));
    let loader = Loader::from_file(input)?;

    for run in 0..runs {
        let project_start = Instant::now();
        let project = Project::new_transient(&loader)?;
        let project_elapsed = project_start.elapsed();

        let analysis_start = Instant::now();
        let config = AnalysisEngineConfig::default().with_worker_limit(worker_limit);
        let engine = AnalysisEngine::with_config(project, config)?;
        engine.analyse()?;
        let analysis_elapsed = analysis_start.elapsed();
        let metrics = engine.metrics();

        let inspection_start = Instant::now();
        let reader = engine.query_reader()?;
        let counts = {
            let project = reader.project()?;
            let mut counts = ProjectCounts {
                functions: project.functions().len(),
                blocks: project.blocks().len(),
                memberships: project
                    .functions()
                    .iter()
                    .map(|function| function.blocks().count())
                    .sum::<usize>(),
                ..ProjectCounts::default()
            };
            for block in project.blocks().iter() {
                counts.blocks_with_context += usize::from(!block.context().is_empty());
                counts.flow_blocks += usize::from(
                    block.is_branch()
                        || block.is_call()
                        || block.is_return()
                        || block.has_unresolved(),
                );
                counts.flow_targets += block.flow_targets().count();
                counts.flow_with_fall_through += usize::from(
                    block
                        .flow_targets()
                        .any(|target| target.kind().is_fall_through()),
                );
            }
            counts
        };
        let inspection_elapsed = inspection_start.elapsed();

        drop(reader);
        let close_start = Instant::now();
        drop(engine);
        let close_elapsed = close_start.elapsed();

        println!(
            "run={run},workers={worker_limit},project_ns={},analysis_ns={},inspection_ns={},\
             close_ns={},dispatches={},\
             functions={},blocks={},memberships={},\
             flow_blocks={},flow_targets={},\
             flow_with_fall_through={},\
             blocks_with_context={},flow_target_bytes={},\
             block_bytes={},context_bytes={},context_update_bytes={}",
            project_elapsed.as_nanos(),
            analysis_elapsed.as_nanos(),
            inspection_elapsed.as_nanos(),
            close_elapsed.as_nanos(),
            metrics.dispatches(),
            counts.functions,
            counts.blocks,
            counts.memberships,
            counts.flow_blocks,
            counts.flow_targets,
            counts.flow_with_fall_through,
            counts.blocks_with_context,
            size_of::<FlowTarget>(),
            size_of::<CodeBlock>(),
            size_of::<ContextSet>(),
            size_of::<ContextUpdate>(),
        );
    }

    Ok(())
}
