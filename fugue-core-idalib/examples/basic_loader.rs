use std::time::Instant;

use fallible_iterator::FallibleIterator;
use fugue_core::attributes;
use fugue_core::loader::{Loadable, LoadableAnalysers, LoadableFromFile};
use fugue_core::project::Project;
use fugue_core_idalib::{IDABinary, ATTRIBUTE_IDA_DATABASE_PATH};

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

        let mut claims = binary.image_segments();
        while let Some(claim) = claims.next()? {
            tracing::info!(
                "{}-{} ({:?})",
                claim.address(),
                claim.address() + claim.size() as usize,
                claim.name()
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

        let mut project = Project::new_transient(&binary)?;
        let mut analyser = binary.analysers().function_recovery()?;

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
