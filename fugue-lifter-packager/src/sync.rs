use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::{Builder, TempDir};

use crate::LifterPackagerError;

const UPSTREAM_REPOSITORY: &str = "https://github.com/NationalSecurityAgency/ghidra.git";

const AARCH64_FILES: &[&str] = &[
    "AARCH64.cspec",
    "AARCH64.dwarf",
    "AARCH64.ldefs",
    "AARCH64.opinion",
    "AARCH64.pspec",
    "AARCH64.slaspec",
    "AARCH64BE.slaspec",
    "AARCH64_AMXext.sinc",
    "AARCH64_AppleSilicon.slaspec",
    "AARCH64_base_PACoptions.sinc",
    "AARCH64_ilp32.cspec",
    "AARCH64_win.cspec",
    "AARCH64base.sinc",
    "AARCH64instructions.sinc",
    "AARCH64ldst.sinc",
    "AARCH64neon.sinc",
    "AARCH64sve.sinc",
    "AppleSilicon.ldefs",
];

const ARM_FILES: &[&str] = &[
    "ARM.cspec",
    "ARM.dwarf",
    "ARM.gdis",
    "ARM.ldefs",
    "ARM.opinion",
    "ARM.sinc",
    "ARM8_be.slaspec",
    "ARM8_le.slaspec",
    "ARM8m_be.slaspec",
    "ARM8m_le.slaspec",
    "ARMCortex.pspec",
    "ARMTHUMBinstructions.sinc",
    "ARM_CDE.sinc",
    "ARM_v45.cspec",
    "ARM_win.cspec",
    "ARMinstructions.sinc",
    "ARMneon.dwarf",
    "ARMneon.sinc",
    "ARMt.pspec",
    "ARMtTHUMB.pspec",
    "ARMv8.sinc",
];

const X86_FILES: &[&str] = &[
    "adx.sinc",
    "avx.sinc",
    "avx2.sinc",
    "avx2_manual.sinc",
    "avx_manual.sinc",
    "bmi1.sinc",
    "bmi2.sinc",
    "cet.sinc",
    "clwb.sinc",
    "fma.sinc",
    "ia.sinc",
    "lockable.sinc",
    "lzcnt.sinc",
    "macros.sinc",
    "mpx.sinc",
    "pclmulqdq.sinc",
    "rdrand.sinc",
    "sgx.sinc",
    "sha.sinc",
    "smx.sinc",
    "x86-64-compat32.pspec",
    "x86-64-gcc.cspec",
    "x86-64-golang.cspec",
    "x86-64-golang.register.info",
    "x86-64-win.cspec",
    "x86-64.dwarf",
    "x86-64.pspec",
    "x86-64.slaspec",
    "x86.dwarf",
    "x86.ldefs",
    "x86.pspec",
    "x86.slaspec",
    "x86gcc.cspec",
    "x86win.cspec",
];

struct SyncTarget {
    source_processor: &'static str,
    destination: &'static str,
    files: &'static [&'static str],
}

const SYNC_TARGETS: &[SyncTarget] = &[
    SyncTarget {
        source_processor: "AARCH64",
        destination: "fugue-lifter-aarch64/data/processors/AARCH64",
        files: AARCH64_FILES,
    },
    SyncTarget {
        source_processor: "ARM",
        destination: "fugue-lifter-arm/data/processors/ARM",
        files: ARM_FILES,
    },
    SyncTarget {
        source_processor: "x86",
        destination: "fugue-lifter-x86/data/processors/x86",
        files: X86_FILES,
    },
];

#[derive(Debug, Clone, Default)]
pub struct SyncOptions {
    dir: Option<PathBuf>,
    reference: Option<String>,
}

impl SyncOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    pub fn with_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }

    pub fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }

    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }
}

pub fn sync_languages(options: &SyncOptions) -> Result<(), LifterPackagerError> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");

    sync_languages_with_repo(workspace_root, options, UPSTREAM_REPOSITORY)
}

fn sync_languages_with_repo(
    workspace_root: &Path,
    options: &SyncOptions,
    repository: &str,
) -> Result<(), LifterPackagerError> {
    if options.dir().is_some() && options.reference().is_some() {
        return Err(LifterPackagerError::invalid_arguments(
            "`--dir` cannot be combined with `--ref`",
        ));
    }

    let source = if let Some(dir) = options.dir() {
        Source::Local(resolve_processors_root(dir)?)
    } else {
        let checkout = checkout_processors(repository, options.reference())?;
        Source::Checkout(checkout)
    };

    stage_and_replace(workspace_root, source.processors_root())
}

enum Source {
    Local(PathBuf),
    Checkout(Checkout),
}

impl Source {
    fn processors_root(&self) -> &Path {
        match self {
            Self::Local(path) => path,
            Self::Checkout(checkout) => checkout.processors_root(),
        }
    }
}

struct Checkout {
    _temporary_directory: TempDir,
    processors_root: PathBuf,
}

impl Checkout {
    fn processors_root(&self) -> &Path {
        &self.processors_root
    }
}

struct StagedTarget {
    _staging_root: TempDir,
    staged_directory: PathBuf,
    destination: PathBuf,
}

fn resolve_processors_root(root: &Path) -> Result<PathBuf, LifterPackagerError> {
    let repository_processors = root.join("Ghidra/Processors");
    if repository_processors.is_dir() {
        return Ok(repository_processors);
    }

    let extracted_processors = root.join("Processors");
    if extracted_processors.is_dir() {
        return Ok(extracted_processors);
    }

    Err(LifterPackagerError::invalid_path("source tree", root))
}

fn checkout_processors(
    repository: &str,
    reference: Option<&str>,
) -> Result<Checkout, LifterPackagerError> {
    let temporary_directory = Builder::new()
        .prefix("lifter-packager-sync-")
        .tempdir()
        .map_err(|source| {
            LifterPackagerError::io(
                "create temporary directory in",
                std::env::temp_dir(),
                source,
            )
        })?;
    let checkout_root = temporary_directory.path().join("ghidra");

    run_git(
        None,
        vec![String::from("init"), checkout_root.display().to_string()],
    )?;
    run_git(
        Some(&checkout_root),
        vec![
            String::from("remote"),
            String::from("add"),
            String::from("origin"),
            String::from(repository),
        ],
    )?;
    run_git(
        Some(&checkout_root),
        vec![
            String::from("sparse-checkout"),
            String::from("init"),
            String::from("--cone"),
        ],
    )?;

    let mut sparse_checkout = vec![String::from("sparse-checkout"), String::from("set")];
    sparse_checkout.extend(SYNC_TARGETS.iter().map(|target| {
        format!(
            "Ghidra/Processors/{}/data/languages",
            target.source_processor
        )
    }));
    run_git(Some(&checkout_root), sparse_checkout)?;

    let reference = match reference {
        Some(reference) => reference.to_owned(),
        None => resolve_latest_stable_release(repository)?,
    };
    run_git(
        Some(&checkout_root),
        vec![
            String::from("fetch"),
            String::from("--depth"),
            String::from("1"),
            String::from("origin"),
            reference,
        ],
    )?;
    run_git(
        Some(&checkout_root),
        vec![
            String::from("checkout"),
            String::from("--detach"),
            String::from("FETCH_HEAD"),
        ],
    )?;

    let processors_root = resolve_processors_root(&checkout_root)?;

    Ok(Checkout {
        _temporary_directory: temporary_directory,
        processors_root,
    })
}

fn resolve_latest_stable_release(repository: &str) -> Result<String, LifterPackagerError> {
    let output = run_git(
        None,
        vec![
            String::from("ls-remote"),
            String::from("--tags"),
            String::from("--refs"),
            String::from(repository),
        ],
    )?;

    latest_stable_release_tag(&output)
        .ok_or_else(|| LifterPackagerError::release_not_found(repository))
}

fn latest_stable_release_tag(output: &str) -> Option<String> {
    let mut best = Option::<(Vec<u32>, String)>::None;

    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let Some(_hash) = parts.next() else {
            continue;
        };
        let Some(tag) = parts.next() else {
            continue;
        };
        let Some(tag) = tag.strip_prefix("refs/tags/") else {
            continue;
        };
        let Some(version) = parse_release_version(tag) else {
            continue;
        };

        let replace = match best.as_ref() {
            Some((best_version, _)) => version > *best_version,
            None => true,
        };

        if replace {
            best = Some((version, tag.to_owned()));
        }
    }

    best.map(|(_, tag)| tag)
}

fn parse_release_version(tag: &str) -> Option<Vec<u32>> {
    let version = tag.strip_prefix("Ghidra_")?.strip_suffix("_build")?;
    if version.is_empty() {
        return None;
    }

    let mut components = Vec::new();
    for component in version.split('.') {
        if component.is_empty() {
            return None;
        }

        let number = component.parse().ok()?;
        components.push(number);
    }

    Some(components)
}

fn stage_and_replace(
    workspace_root: &Path,
    processors_root: &Path,
) -> Result<(), LifterPackagerError> {
    let mut staged_targets = Vec::new();

    for target in SYNC_TARGETS {
        let destination = workspace_root.join(target.destination);
        let destination_parent = destination
            .parent()
            .expect("sync target destination must have a parent");
        let staging_root = Builder::new()
            .prefix(".language-sync-")
            .tempdir_in(destination_parent)
            .map_err(|source| {
                LifterPackagerError::io("create temporary directory in", destination_parent, source)
            })?;
        let staged_directory = staging_root.path().join(target.source_processor);

        fs::create_dir(&staged_directory).map_err(|source| {
            LifterPackagerError::io("create directory", &staged_directory, source)
        })?;

        let source_directory = processors_root
            .join(target.source_processor)
            .join("data/languages");
        for file in target.files {
            let source = source_directory.join(file);
            if !source.is_file() {
                return Err(LifterPackagerError::missing_path("source file", source));
            }

            let staged_file = staged_directory.join(file);
            fs::copy(&source, &staged_file)
                .map_err(|source| LifterPackagerError::io("write file", &staged_file, source))?;
        }

        staged_targets.push(StagedTarget {
            _staging_root: staging_root,
            staged_directory,
            destination,
        });
    }

    for staged_target in staged_targets {
        replace_directory(&staged_target.staged_directory, &staged_target.destination)?;
    }

    Ok(())
}

fn replace_directory(
    staged_directory: &Path,
    destination: &Path,
) -> Result<(), LifterPackagerError> {
    let destination_parent = destination
        .parent()
        .expect("sync target destination must have a parent");
    let destination_name = destination
        .file_name()
        .expect("sync target destination must have a name")
        .to_string_lossy();
    let backup = unique_work_path(destination_parent, &destination_name, "backup");

    if destination.exists() {
        fs::rename(destination, &backup)
            .map_err(|source| LifterPackagerError::rename_path(destination, &backup, source))?;
    }

    if let Err(source) = fs::rename(staged_directory, destination) {
        if backup.exists() {
            let _ = fs::rename(&backup, destination);
        }

        return Err(LifterPackagerError::rename_path(
            staged_directory,
            destination,
            source,
        ));
    }

    if backup.exists() {
        fs::remove_dir_all(&backup)
            .map_err(|source| LifterPackagerError::io("remove directory", &backup, source))?;
    }

    Ok(())
}

fn unique_work_path(parent: &Path, name: &str, suffix: &str) -> PathBuf {
    let process_id = std::process::id();

    for attempt in 0..1024_u32 {
        let candidate = parent.join(format!(".{name}.{suffix}.{process_id}.{attempt}"));
        if !candidate.exists() {
            return candidate;
        }
    }

    parent.join(format!(".{name}.{suffix}.{process_id}.overflow"))
}

fn run_git(current_dir: Option<&Path>, args: Vec<String>) -> Result<String, LifterPackagerError> {
    let command = render_command("git", &args);

    let mut process = Command::new("git");
    process.args(&args);
    if let Some(current_dir) = current_dir {
        process.current_dir(current_dir);
    }

    let output = process
        .output()
        .map_err(|source| LifterPackagerError::CommandSpawn {
            command: command.clone(),
            source,
        })?;

    if !output.status.success() {
        return Err(LifterPackagerError::CommandFailed {
            command,
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn render_command(program: &str, args: &[String]) -> String {
    let mut rendered = String::from(program);
    for argument in args {
        rendered.push(' ');
        rendered.push_str(argument);
    }

    rendered
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{
        latest_stable_release_tag, parse_release_version, sync_languages_with_repo, SyncOptions,
        AARCH64_FILES, ARM_FILES, SYNC_TARGETS, X86_FILES,
    };

    fn create_source_tree(root: &Path) {
        for target in SYNC_TARGETS {
            let source_directory = root
                .join("Ghidra/Processors")
                .join(target.source_processor)
                .join("data/languages");
            fs::create_dir_all(&source_directory).unwrap();
            for file in target.files {
                fs::write(source_directory.join(file), format!("source:{file}")).unwrap();
            }
        }
    }

    fn create_workspace_tree(root: &Path) {
        for target in SYNC_TARGETS {
            let destination_directory = root.join(target.destination);
            fs::create_dir_all(&destination_directory).unwrap();
            fs::write(destination_directory.join("stale.txt"), "stale").unwrap();
        }
    }

    #[test]
    fn parses_latest_stable_release_tag() {
        let tags = "\
deadbeef refs/tags/Ghidra_11.4_build\n\
deadbeef refs/tags/Ghidra_12.0_build\n\
deadbeef refs/tags/Ghidra_12.0.4_build\n\
deadbeef refs/tags/Ghidra_12.1_RC1_build\n";

        let latest = latest_stable_release_tag(tags);

        assert_eq!(latest.as_deref(), Some("Ghidra_12.0.4_build"));
    }

    #[test]
    fn rejects_non_stable_release_tags() {
        assert_eq!(parse_release_version("Ghidra_12.1_RC1_build"), None);
        assert_eq!(parse_release_version("nightly"), None);
    }

    #[test]
    fn syncs_from_local_directory_and_removes_stale_files() {
        let root = tempfile::tempdir().unwrap();
        let workspace_root = root.path().join("workspace");
        let source_root = root.path().join("ghidra");

        create_workspace_tree(&workspace_root);
        create_source_tree(&source_root);

        sync_languages_with_repo(
            &workspace_root,
            &SyncOptions::new().with_dir(&source_root),
            "unused",
        )
        .unwrap();

        for target in SYNC_TARGETS {
            let destination_directory = workspace_root.join(target.destination);
            assert!(!destination_directory.join("stale.txt").exists());

            for file in target.files {
                let path = destination_directory.join(file);
                assert_eq!(fs::read_to_string(path).unwrap(), format!("source:{file}"));
            }
        }
    }

    #[test]
    fn sync_failure_preserves_existing_directories() {
        let root = tempfile::tempdir().unwrap();
        let workspace_root = root.path().join("workspace");
        let source_root = root.path().join("ghidra");

        create_workspace_tree(&workspace_root);
        create_source_tree(&source_root);

        let missing = source_root
            .join("Ghidra/Processors/x86/data/languages")
            .join(X86_FILES[0]);
        fs::remove_file(missing).unwrap();

        let error = sync_languages_with_repo(
            &workspace_root,
            &SyncOptions::new().with_dir(&source_root),
            "unused",
        )
        .unwrap_err();

        assert!(matches!(
            error,
            crate::LifterPackagerError::MissingPath {
                kind: "source file",
                ..
            }
        ));

        for target in SYNC_TARGETS {
            let destination_directory = workspace_root.join(target.destination);
            assert_eq!(
                fs::read_to_string(destination_directory.join("stale.txt")).unwrap(),
                "stale"
            );
        }
    }

    #[test]
    fn manifests_cover_expected_file_counts() {
        assert_eq!(AARCH64_FILES.len(), 18);
        assert_eq!(ARM_FILES.len(), 21);
        assert_eq!(X86_FILES.len(), 34);
    }
}
