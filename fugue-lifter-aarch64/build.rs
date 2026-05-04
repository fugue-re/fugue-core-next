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

    let input = Path::new("data/generated").join(format!("{output}.gz"));
    let output = PathBuf::from_iter([env::var("OUT_DIR").expect("OUT_DIR").as_ref(), output]);

    fugue_lifter_packager::unpack_lifter(input, output)?;

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

    #[cfg(feature = "aarch64-be")]
    build_lifter("AARCH64:BE:64:v8A", &[], "aarch64_be.rs")?;
    #[cfg(feature = "aarch64-le")]
    build_lifter("AARCH64:LE:64:v8A", &[], "aarch64_le.rs")?;

    Ok(())
}
