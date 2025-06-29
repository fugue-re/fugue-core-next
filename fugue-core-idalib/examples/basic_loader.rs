use fallible_iterator::FallibleIterator;

use fugue_base::analysis::core::functions::FunctionRecovery;
use fugue_base::analysis::AnalysisPass;
use fugue_base::loader::{Loadable, LoadableFromFile};

use fugue_base::attributes;
use fugue_base::project::Project;
use fugue_base::storage::PersistentStorageProvider;
use fugue_base::types::attributes::ATTRIBUTE_PROJECT_PATH;

use fugue_core_idalib::{IDABinary, IDAFunctionBuilder, ATTRIBUTE_IDA_DATABASE_PATH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let binary = IDABinary::from_file_with(
            "tests/test",
            attributes! {
                ATTRIBUTE_IDA_DATABASE_PATH => "tests/test-non-clashing.idb",
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

        for sym in binary.locals().iter() {
            tracing::info!("local symbol {sym}");
        }

        for sym in binary
            .externs()
            .map(|externs| externs.iter())
            .into_iter()
            .flatten()
        {
            tracing::info!("external symbol {sym}");
        }

        let mut project = Project::new_with::<PersistentStorageProvider>(
            &binary,
            attributes! {
                ATTRIBUTE_PROJECT_PATH => "/tmp/test-project.fdbz",
            },
        )?;
        let mut analyser = FunctionRecovery::new();

        analyser.add_function_builder_initialisation_pass(
            "ida-blocks-and-edges",
            IDAFunctionBuilder::new(binary.database()),
        );

        analyser.analyse(&mut project)?;

        Ok(())
    })
}
