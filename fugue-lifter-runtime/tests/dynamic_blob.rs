#![cfg(feature = "dynamic")]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use fugue_lifter_packager::pack_blob;
use fugue_lifter_runtime::dynamic::LanguageBuilder;
use fugue_lifter_runtime::dynamic::LanguageLoadError;
use fugue_lifter_runtime::dynamic::build::BuildError;
use fugue_lifter_runtime::language::{Language, LanguageId};
use fugue_lifter_runtime::Lifter;
use fugue_lifter_runtime::operand::Operands;
use fugue_lifter_runtime::pcode::PCodeOp;
use tempfile::TempDir;

fn x86_specs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fugue-lifter-x86")
        .join("data")
        .join("processors")
}

fn arm_specs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fugue-lifter-arm")
        .join("data")
        .join("processors")
}

struct CachedBlob {
    path: PathBuf,
    _dir: TempDir,
}

impl CachedBlob {
    fn build(specs: &Path, language: &str, file_name: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(file_name);
        pack_blob(specs, language, &path).expect("pack_blob succeeds");
        Self { path, _dir: dir }
    }
}

fn x86_64_blob_path() -> &'static Path {
    static BLOB: OnceLock<CachedBlob> = OnceLock::new();
    &BLOB
        .get_or_init(|| CachedBlob::build(&x86_specs(), "x86:LE:64:default", "x86_64.flift"))
        .path
}

fn arm_le_blob_path() -> &'static Path {
    static BLOB: OnceLock<CachedBlob> = OnceLock::new();
    &BLOB
        .get_or_init(|| CachedBlob::build(&arm_specs(), "ARM:LE:32:v8", "arm_le.flift"))
        .path
}

fn x86_64_builder() -> LanguageBuilder {
    LanguageBuilder::from_file(x86_64_blob_path()).expect("load x86_64 blob")
}

fn arm_le_builder() -> LanguageBuilder {
    LanguageBuilder::from_file(arm_le_blob_path()).expect("load arm_le blob")
}

const X86_64_FIXTURES: &[(u64, &[u8])] = &[
    (0x1000, &[0x90]),
    (0x1000, &[0x48, 0x89, 0xc8]),
    (0x1000, &[0x48, 0x01, 0xc8]),
    (0x1000, &[0xc3]),
    (0x1000, &[0xe8, 0x00, 0x00, 0x00, 0x00]),
    (0x1000, &[0xeb, 0x00]),
    (0x1000, &[0x74, 0x00]),
    (0x1000, &[0x48, 0x89, 0x04, 0x24]),
    (0x1000, &[0x48, 0x83, 0xec, 0x10]),
    (0x1000, &[0x55]),
    (0x1000, &[0x5d]),
    (0x1000, &[0x48, 0x31, 0xc0]),
    (0x1000, &[0xff, 0xc0]),
    (0x1000, &[0x0f, 0x05]),
];

const ARM_LE_FIXTURES: &[(u64, &[u8])] = &[
    (0x1000, &[0x00, 0x00, 0xa0, 0xe3]),
    (0x1000, &[0x01, 0x00, 0x80, 0xe2]),
    (0x1000, &[0x0e, 0xf0, 0xa0, 0xe1]),
];

fn lift_static_x86_64(addr: u64, bytes: &[u8]) -> (Option<usize>, String, Vec<PCodeOp>, Operands) {
    let mut lifter = fugue_lifter_x86::x86_64::LifterFactory::new_default();
    let mut disasm = String::new();
    let mut ops = Vec::new();
    let mut operands = Operands::new();
    let _ = lifter.disassemble(addr, bytes, &mut disasm);
    let _ = lifter.operands(addr, bytes, &mut operands);
    let length = lifter.lift(addr, bytes, &mut ops);
    (length, disasm, ops, operands)
}

fn lift_static_arm_le(addr: u64, bytes: &[u8]) -> (Option<usize>, String, Vec<PCodeOp>, Operands) {
    let mut lifter = fugue_lifter_arm::le::LifterFactory::new_v8();
    let mut disasm = String::new();
    let mut ops = Vec::new();
    let mut operands = Operands::new();
    let _ = lifter.disassemble(addr, bytes, &mut disasm);
    let _ = lifter.operands(addr, bytes, &mut operands);
    let length = lifter.lift(addr, bytes, &mut ops);
    (length, disasm, ops, operands)
}

fn lift_dynamic(
    lifter: &mut Lifter,
    addr: u64,
    bytes: &[u8],
) -> (Option<usize>, String, Vec<PCodeOp>, Operands) {
    let mut disasm = String::new();
    let mut ops = Vec::new();
    let mut operands = Operands::new();
    let _ = lifter.disassemble(addr, bytes, &mut disasm);
    let _ = lifter.operands(addr, bytes, &mut operands);
    let length = lifter.lift(addr, bytes, &mut ops);
    (length, disasm, ops, operands)
}

fn assert_parity(
    label: &str,
    addr: u64,
    bytes: &[u8],
    expected: &(Option<usize>, String, Vec<PCodeOp>, Operands),
    actual: &(Option<usize>, String, Vec<PCodeOp>, Operands),
) {
    assert_eq!(
        expected.0, actual.0,
        "{label} length mismatch at {addr:#x} for {bytes:02x?}"
    );
    assert_eq!(
        expected.1, actual.1,
        "{label} disassembly mismatch at {addr:#x} for {bytes:02x?}: expected `{}`, got `{}`",
        expected.1, actual.1
    );
    assert_eq!(
        expected.2, actual.2,
        "{label} pcode mismatch at {addr:#x} for {bytes:02x?}: expected {:#?}, got {:#?}",
        expected.2, actual.2
    );
    assert_eq!(
        expected.3, actual.3,
        "{label} operands mismatch at {addr:#x} for {bytes:02x?}"
    );
}

#[test]
fn parity_x86_64_disasm_and_pcode() {
    let mut lifter = x86_64_builder().lifter(2);

    for (addr, bytes) in X86_64_FIXTURES {
        let expected = lift_static_x86_64(*addr, bytes);
        let actual = lift_dynamic(&mut lifter, *addr, bytes);
        assert_parity("x86_64", *addr, bytes, &expected, &actual);
    }
}

#[test]
fn parity_arm_le() {
    let mut lifter = arm_le_builder().lifter(2);

    for (addr, bytes) in ARM_LE_FIXTURES {
        let expected = lift_static_arm_le(*addr, bytes);
        let actual = lift_dynamic(&mut lifter, *addr, bytes);
        assert_parity("arm_le", *addr, bytes, &expected, &actual);
    }
}

#[test]
fn multi_language_concurrent() {
    let mut x86_lifter = x86_64_builder().lifter(2);
    let mut arm_lifter = arm_le_builder().lifter(2);

    assert!(
        !std::ptr::eq(x86_lifter.language(), arm_lifter.language()),
        "different languages must be different pointers"
    );

    for ((x86_addr, x86_bytes), (arm_addr, arm_bytes)) in
        X86_64_FIXTURES.iter().zip(ARM_LE_FIXTURES)
    {
        let x86_expected = lift_static_x86_64(*x86_addr, x86_bytes);
        let x86_actual = lift_dynamic(&mut x86_lifter, *x86_addr, x86_bytes);
        assert_parity("x86_64", *x86_addr, x86_bytes, &x86_expected, &x86_actual);

        let arm_expected = lift_static_arm_le(*arm_addr, arm_bytes);
        let arm_actual = lift_dynamic(&mut arm_lifter, *arm_addr, arm_bytes);
        assert_parity("arm_le", *arm_addr, arm_bytes, &arm_expected, &arm_actual);
    }
}

#[test]
fn registry_dedup() {
    let first = x86_64_builder().language();
    let second = x86_64_builder().language();

    assert!(
        std::ptr::eq(first, second),
        "loading the same language twice must return the same &'static Language"
    );

    let parsed = "x86:LE:64:default".parse::<LanguageId>().unwrap();
    let looked_up = Language::lookup(&parsed).expect("registry knows about previously loaded id");
    assert!(
        std::ptr::eq(first, looked_up),
        "lookup returns the registered pointer"
    );
}

#[test]
fn from_sleigh_requires_precompiled_sla() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let result = LanguageBuilder::from_sleigh(scratch.path(), "x86:LE:64:default");
    match result {
        Err(LanguageLoadError::Build(BuildError::SleighSlaMissing { language, .. })) => {
            assert_eq!(language, "x86:LE:64:default");
        }
        Err(LanguageLoadError::Build(BuildError::Language(language))) => {
            assert_eq!(language, "x86:LE:64:default");
        }
        Err(other) => panic!("unexpected error from from_sleigh: {other}"),
        Ok(_) => panic!("from_sleigh must not invoke a compiler at runtime"),
    }
}

#[test]
fn packager_smoke() {
    let mut lifter = arm_le_builder().lifter(2);

    for (addr, bytes) in ARM_LE_FIXTURES {
        let expected = lift_static_arm_le(*addr, bytes);
        let actual = lift_dynamic(&mut lifter, *addr, bytes);
        assert_parity("arm_le-blob", *addr, bytes, &expected, &actual);
    }
}

#[test]
fn language_builder_loads_blob_metadata() {
    let builder = LanguageBuilder::from_file(x86_64_blob_path()).expect("builder loads blob");
    assert_eq!(builder.language().id(), "x86:LE:64:default");
}
