use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};

use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
use fugue_core::loader::Loader;
use fugue_core::project::Project;
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn Error>> {
    let inputs = env::args().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    let inputs = if inputs.is_empty() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        vec![root.join("tests/libipmi.so"), root.join("tests/ls.elf")]
    } else {
        inputs
    };

    for input in inputs {
        let loader = Loader::from_file(&input)?;
        let project = Project::new_transient(&loader)?;
        let config = AnalysisEngineConfig::default().with_worker_limit(1);
        let engine = AnalysisEngine::with_config(project, config)?;
        engine.analyse()?;

        let reader = engine.query_reader()?;
        let functions = {
            let project = reader.project()?;
            project
                .functions()
                .iter()
                .map(|function| function.id())
                .collect::<Vec<_>>()
        };

        let mut digest = Sha256::new();
        let mut lifted = 0usize;
        let mut statements = 0usize;
        let mut expressions = 0usize;
        for function in functions {
            let Some(ecode) = reader.ecode(function)? else {
                continue;
            };
            lifted += 1;
            statements += ecode.statements().len();
            expressions += ecode.expressions().len();
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(ecode.as_ref())?;
            digest.update(bytes.as_slice());
        }

        println!(
            "{}: lifted={lifted} statements={statements} expressions={expressions} digest={:x}",
            input.display(),
            digest.finalize()
        );
    }

    Ok(())
}
