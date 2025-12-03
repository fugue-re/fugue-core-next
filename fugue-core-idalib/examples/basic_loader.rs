use std::time::Instant;

use fallible_iterator::FallibleIterator;

use fugue_core::analysis::function::FunctionRecovery;
use fugue_core::analysis::AnalysisPass;
use fugue_core::attributes;
use fugue_core::ir::traits::FunctionTable;
use fugue_core::loader::{Loadable, LoadableFromFile};
use fugue_core::project::InMemoryProject;

use fugue_core_idalib::{IDABinary, IDAFunctionBuilder, ATTRIBUTE_IDA_DATABASE_PATH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        idalib::force_batch_mode();

        tracing::info!("loading binary with idalib");

        let binary = IDABinary::from_file_with(
            "tests/dive",
            attributes! {
                ATTRIBUTE_IDA_DATABASE_PATH => "tests/dive-non-clashing.idb",
            },
        )?;

        let mut segments = binary.segments();
        while let Some(segm) = segments.next()? {
            tracing::info!(
                "{}-{} ({:?})",
                segm.address(),
                segm.address() + segm.len(),
                segm.name()
            );
        }
        tracing::info!("architecture: {}", binary.architecture());

        for (_, sym) in binary.symbols().iter() {
            if sym.is_local() {
                tracing::info!("local symbol: {} at {:#x}", sym.symbol(), sym.address());
            } else if sym.is_extern() {
                tracing::info!("global symbol: {} at {:#x}", sym.symbol(), sym.address());
            }
        }

        let mut project = InMemoryProject::new(&binary)?;
        let mut analyser = FunctionRecovery::new();

        analyser.add_initialisation_pass(
            "ida-function-builder",
            IDAFunctionBuilder::new(binary.database()),
        );

        let t0 = Instant::now();

        tracing::info!("recovering functions via idalib");

        analyser.analyse(&mut project)?;

        let tt = t0.elapsed();

        tracing::info!(
            "function recovery completed in {}ms; identified {} functions",
            tt.as_millis(),
            project.functions().len()
        );

        Ok(())
    })
}
