use std::fs::File;
use std::io::{copy, BufWriter, Write};
use std::path::Path;

use anyhow::Context;

pub type LifterPackagerError = anyhow::Error;

pub fn unpack_lifter(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<(), LifterPackagerError> {
    let input = input.as_ref();
    let output = output.as_ref();

    if !input.exists() {
        return Err(anyhow::anyhow!(
            "input file `{}` does not exist",
            input.display()
        ));
    }

    let mut deflated = flate2::read::GzDecoder::new(
        File::open(input)
            .with_context(|| format!("failed to read input file `{}`", input.display()))?,
    );
    let mut writer = BufWriter::new(
        File::create(output)
            .with_context(|| format!("cannot create output file `{}`", output.display()))?,
    );

    copy(&mut deflated, &mut writer)
        .with_context(|| format!("cannot write to output file `{}`", output.display()))?;

    Ok(())
}

pub fn pack_lifter(
    specs: impl AsRef<Path>,
    language: &str,
    output: impl AsRef<Path>,
) -> Result<(), LifterPackagerError> {
    let specs = specs.as_ref();
    let output = output.as_ref();

    if !specs.exists() || !specs.is_dir() {
        return Err(anyhow::anyhow!(
            "language specification directory `{}` cannot be read",
            specs.display()
        ));
    }

    let lifter = fugue_lifter_codegen::build_with(specs, language, true)?;

    let mut writer = flate2::write::GzEncoder::new(
        BufWriter::new(
            File::create(&output)
                .with_context(|| format!("cannot create output file `{}`", output.display()))?,
        ),
        Default::default(),
    );

    writer
        .write_all(lifter.as_ref())
        .with_context(|| format!("cannot write output file `{}`", output.display()))?;
    writer
        .finish()
        .with_context(|| format!("cannot finalise output file `{}`", output.display()))?;

    Ok(())
}
