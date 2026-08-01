use std::env;
use std::error::Error;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::Instant;

use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
use fugue_core::ir::{CodeBlock, Insn, InsnTarget};
use fugue_core::lifter::{ContextSet, ContextUpdate};
use fugue_core::loader::Loader;
use fugue_core::project::Project;

fn main() -> Result<(), Box<dyn Error>> {
    if env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
        let reader = engine.query_reader()?;
        let project = reader.project()?;
        let functions = project.functions().len();
        let blocks = project.blocks().len();
        let memberships = project
            .functions()
            .iter()
            .map(|function| function.blocks().count())
            .sum::<usize>();
        let mut flow_insns = 0usize;
        let mut flow_with_fall_through = 0usize;
        let mut insns = 0usize;
        let mut blocks_with_context = 0usize;
        for block in project.blocks().iter() {
            blocks_with_context += usize::from(!block.context().is_empty());
            insns += block.instructions().len();
            for insn in block.instructions() {
                if insn.is_flow() {
                    flow_insns += 1;
                    flow_with_fall_through += usize::from(insn.has_fall_through());
                }
            }
        }
        println!(
            "run={run},workers={worker_limit},project_ns={},analysis_ns={},dispatches={},\
             functions={functions},blocks={blocks},memberships={memberships},insns={insns},\
             flow_insns={flow_insns},flow_with_fall_through={flow_with_fall_through},\
             blocks_with_context={blocks_with_context},insn_bytes={},target_bytes={},\
             block_bytes={},context_bytes={},context_update_bytes={}",
            project_elapsed.as_nanos(),
            analysis_elapsed.as_nanos(),
            metrics.dispatches(),
            size_of::<Insn>(),
            size_of::<InsnTarget>(),
            size_of::<CodeBlock>(),
            size_of::<ContextSet>(),
            size_of::<ContextUpdate>(),
        );
    }

    Ok(())
}
