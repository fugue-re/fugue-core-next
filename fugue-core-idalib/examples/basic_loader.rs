use fallible_iterator::FallibleIterator;
use fugue_base::loader::{Loadable, LoadableFromFile};
use fugue_core_idalib::IDABinary;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let binary = IDABinary::from_file("tests/test")?;
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

        Ok(())
    })
}
