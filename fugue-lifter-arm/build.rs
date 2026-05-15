use std::env;
use std::path::PathBuf;

#[cfg(all(not(feature = "bundled"), not(feature = "compiled")))]
compile_error!("Either the 'bundled' or 'compiled' feature must be enabled.");

#[cfg(all(feature = "bundled", feature = "compiled"))]
compile_error!("Only one of the 'bundled' or 'compiled' features can be enabled at the same time.");

#[cfg(feature = "bundled")]
fn build_lifter(
    _arch: &str,
    _variants: &[&str],
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;

    use fugue_lifter_packager::Packager;

    let input = Path::new("data/generated").join(format!("{output}.gz"));
    let output = PathBuf::from_iter([env::var("OUT_DIR").expect("OUT_DIR").as_ref(), output]);

    Packager::new().unpack_lifter(input, output)?;

    Ok(())
}

#[cfg(feature = "compiled")]
fn build_lifter(
    arch: &str,
    variants: &[&str],
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::path::Path;

    let mut options = fugue_lifter_codegen::BuildOptions::new();
    if Path::new("data/patches").is_dir() {
        options.add_patch("data/patches");
    }
    options.add_variants(variants.iter().copied());

    let lifter = fugue_lifter_codegen::build_with("data/processors", arch, options)?;
    let output = PathBuf::from_iter([env::var("OUT_DIR").expect("OUT_DIR").as_ref(), output]);

    let mut writer = BufWriter::new(File::create(&output)?);
    writer.write_all(lifter.as_ref())?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=data/generated");
    println!("cargo::rerun-if-changed=data/processors");
    println!("cargo::rerun-if-changed=data/patches");

    #[cfg(feature = "arm-be")]
    build_lifter("ARM:BE:32:v8", &["v8T"], "arm_be.rs")?;
    #[cfg(feature = "arm-le")]
    build_lifter("ARM:LE:32:v8", &["v8T"], "arm_le.rs")?;

    Ok(())
}
