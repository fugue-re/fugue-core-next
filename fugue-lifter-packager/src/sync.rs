use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use tempfile::{Builder, TempDir};
use thiserror::Error;

use crate::Packager;

const UPSTREAM_REPOSITORY: &str = "https://github.com/NationalSecurityAgency/ghidra.git";

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("`{command}` failed with status {status}: {stderr}")]
    CommandFailed {
        command: String,
        status: ExitStatus,
        stderr: String,
    },
    #[error("cannot run `{command}`")]
    CommandSpawn {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("{kind} `{path}` cannot be read")]
    InvalidPath { kind: &'static str, path: PathBuf },
    #[error("cannot {action} `{path}`")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("missing {kind} `{path}`")]
    MissingPath { kind: &'static str, path: PathBuf },
    #[error("no stable release tag could be resolved from `{repository}`")]
    ReleaseNotFound { repository: String },
    #[error("cannot rename `{from}` to `{to}`")]
    RenamePath {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl SyncError {
    fn invalid_path(kind: &'static str, path: impl AsRef<Path>) -> Self {
        Self::InvalidPath {
            kind,
            path: path.as_ref().to_path_buf(),
        }
    }

    fn missing_path(kind: &'static str, path: impl AsRef<Path>) -> Self {
        Self::MissingPath {
            kind,
            path: path.as_ref().to_path_buf(),
        }
    }

    fn io(action: &'static str, path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    fn rename_path(from: impl AsRef<Path>, to: impl AsRef<Path>, source: io::Error) -> Self {
        Self::RenamePath {
            from: from.as_ref().to_path_buf(),
            to: to.as_ref().to_path_buf(),
            source,
        }
    }

    fn release_not_found(repository: impl Into<String>) -> Self {
        Self::ReleaseNotFound {
            repository: repository.into(),
        }
    }
}

struct SyncTarget {
    source_processor: &'static str,
    destination: &'static str,
}

const SYNC_TARGETS: &[SyncTarget] = &[
    SyncTarget {
        source_processor: "AARCH64",
        destination: "fugue-lifter-aarch64/data/processors/AARCH64",
    },
    SyncTarget {
        source_processor: "ARM",
        destination: "fugue-lifter-arm/data/processors/ARM",
    },
    SyncTarget {
        source_processor: "x86",
        destination: "fugue-lifter-x86/data/processors/x86",
    },
];

impl Packager {
    pub fn sync_local(&self, local_ghidra: impl AsRef<Path>) -> Result<(), SyncError> {
        SyncJob::at_workspace_root().local(local_ghidra.as_ref())
    }

    pub fn sync_upstream(&self, reference: Option<&str>) -> Result<(), SyncError> {
        SyncJob::at_workspace_root().upstream(UPSTREAM_REPOSITORY, reference)
    }
}

struct SyncJob<'a> {
    workspace_root: &'a Path,
}

impl<'a> SyncJob<'a> {
    fn at_workspace_root() -> SyncJob<'static> {
        SyncJob {
            workspace_root: Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("workspace root"),
        }
    }

    fn local(&self, ghidra_root: &Path) -> Result<(), SyncError> {
        let processors_root = Checkout::resolve_processors_root(ghidra_root)?;
        self.stage_and_commit(&processors_root)
    }

    fn upstream(&self, repository: &str, reference: Option<&str>) -> Result<(), SyncError> {
        let checkout = Checkout::clone_from(repository, reference)?;
        self.stage_and_commit(checkout.processors_root())
    }

    fn stage_and_commit(&self, processors_root: &Path) -> Result<(), SyncError> {
        let staged = SYNC_TARGETS
            .iter()
            .map(|target| StagedTarget::stage(self.workspace_root, target, processors_root))
            .collect::<Result<Vec<_>, _>>()?;

        for target in staged {
            target.commit()?;
        }
        Ok(())
    }
}

struct Checkout {
    #[allow(unused)]
    root: TempDir,
    processors_root: PathBuf,
}

impl Checkout {
    fn processors_root(&self) -> &Path {
        &self.processors_root
    }

    fn clone_from(repository: &str, reference: Option<&str>) -> Result<Self, SyncError> {
        let root = Builder::new()
            .prefix("lifter-packager-sync-")
            .tempdir()
            .map_err(|source| {
                SyncError::io(
                    "create temporary directory in",
                    std::env::temp_dir(),
                    source,
                )
            })?;
        let checkout_root = root.path().join("ghidra");

        GitRepo::global().run(&["init", &checkout_root.to_string_lossy()])?;

        let repo = GitRepo::at(&checkout_root);
        repo.run(&["remote", "add", "origin", repository])?;
        repo.run(&["sparse-checkout", "init", "--cone"])?;
        repo.run(&Self::sparse_checkout_args())?;

        let reference = match reference {
            Some(reference) => reference.to_owned(),
            None => Self::latest_stable_release(repository)?,
        };
        repo.run(&["fetch", "--depth", "1", "origin", &reference])?;
        repo.run(&["checkout", "--detach", "FETCH_HEAD"])?;

        let processors_root = Self::resolve_processors_root(&checkout_root)?;

        Ok(Self {
            root,
            processors_root,
        })
    }

    fn sparse_checkout_args() -> Vec<String> {
        let mut args = Vec::with_capacity(SYNC_TARGETS.len() + 2);
        args.push(String::from("sparse-checkout"));
        args.push(String::from("set"));
        for target in SYNC_TARGETS {
            let processor = target.source_processor;
            args.push(format!("Ghidra/Processors/{processor}/data/languages"));
        }
        args
    }

    fn latest_stable_release(repository: &str) -> Result<String, SyncError> {
        let output = GitRepo::global().run(&["ls-remote", "--tags", "--refs", repository])?;
        ReleaseTag::pick_latest(&output).ok_or_else(|| SyncError::release_not_found(repository))
    }

    fn resolve_processors_root(root: &Path) -> Result<PathBuf, SyncError> {
        for relative in ["Ghidra/Processors", "Processors"] {
            let candidate = root.join(relative);
            if candidate.is_dir() {
                return Ok(candidate);
            }
        }
        Err(SyncError::invalid_path("source tree", root))
    }
}

struct GitRepo<'a> {
    working_dir: Option<&'a Path>,
}

impl<'a> GitRepo<'a> {
    fn global() -> Self {
        Self { working_dir: None }
    }

    fn at(working_dir: &'a Path) -> Self {
        Self {
            working_dir: Some(working_dir),
        }
    }

    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<String, SyncError> {
        let mut process = Command::new("git");
        process.args(args);
        if let Some(dir) = self.working_dir {
            process.current_dir(dir);
        }

        let render = || {
            let mut rendered = String::from("git");
            for arg in args {
                rendered.push(' ');
                rendered.push_str(&arg.as_ref().to_string_lossy());
            }
            rendered
        };

        let output = process.output().map_err(|source| SyncError::CommandSpawn {
            command: render(),
            source,
        })?;

        if !output.status.success() {
            return Err(SyncError::CommandFailed {
                command: render(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

struct ReleaseTag;

impl ReleaseTag {
    fn pick_latest(ls_remote_output: &str) -> Option<String> {
        let mut best = Option::<(Vec<u32>, String)>::None;

        for line in ls_remote_output.lines() {
            let mut parts = line.split_whitespace();
            let Some(_hash) = parts.next() else { continue };
            let Some(tag) = parts.next() else { continue };
            let Some(tag) = tag.strip_prefix("refs/tags/") else {
                continue;
            };
            let Some(version) = Self::parse_version(tag) else {
                continue;
            };

            let replace = best
                .as_ref()
                .map_or(true, |(best_version, _)| version > *best_version);
            if replace {
                best = Some((version, tag.to_owned()));
            }
        }

        best.map(|(_, tag)| tag)
    }

    fn parse_version(tag: &str) -> Option<Vec<u32>> {
        let version = tag.strip_prefix("Ghidra_")?.strip_suffix("_build")?;
        if version.is_empty() {
            return None;
        }
        version.split('.').map(|c| c.parse().ok()).collect()
    }
}

struct LanguageDir<'a> {
    path: &'a Path,
}

impl<'a> LanguageDir<'a> {
    fn new(path: &'a Path) -> Self {
        Self { path }
    }

    fn whitelist(&self) -> Result<Vec<String>, SyncError> {
        if !self.path.is_dir() {
            return Err(SyncError::invalid_path(
                "vendored language directory",
                self.path,
            ));
        }

        let mut files = Vec::new();
        for entry in fs::read_dir(self.path)
            .map_err(|source| SyncError::io("read directory", self.path, source))?
        {
            let entry =
                entry.map_err(|source| SyncError::io("read directory", self.path, source))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                files.push(name.to_owned());
            }
        }
        files.sort();
        Ok(files)
    }

    fn copy_file_from(&self, source: &LanguageDir<'_>, name: &str) -> Result<(), SyncError> {
        let source_file = source.path.join(name);
        if !source_file.is_file() {
            return Err(SyncError::missing_path("source file", source_file));
        }
        let destination = self.path.join(name);
        fs::copy(&source_file, &destination)
            .map_err(|source| SyncError::io("write file", &destination, source))?;
        Ok(())
    }

    fn missing_sinc_includes(&self) -> Result<Vec<String>, SyncError> {
        let mut missing = Vec::new();

        for file in self.whitelist()? {
            if !file.ends_with(".slaspec") {
                continue;
            }
            let path = self.path.join(file);
            let contents =
                fs::read(&path).map_err(|source| SyncError::io("read file", &path, source))?;
            let contents = String::from_utf8_lossy(&contents);
            for include in Self::extract_sinc_includes(&contents) {
                if !self.path.join(&include).exists() && !missing.contains(&include) {
                    missing.push(include);
                }
            }
        }

        Ok(missing)
    }

    fn extract_sinc_includes(contents: &str) -> Vec<String> {
        let mut includes = Vec::new();
        let mut remainder = contents;
        let prefix = "@include \"";

        while let Some(start) = remainder.find(prefix) {
            remainder = &remainder[start + prefix.len()..];
            let Some(end) = remainder.find('"') else {
                break;
            };
            let include = &remainder[..end];
            if include.ends_with(".sinc") && !includes.iter().any(|value| value == include) {
                includes.push(include.to_owned());
            }
            remainder = &remainder[end + 1..];
        }

        includes
    }
}

struct StagedTarget {
    staging_root: TempDir,
    staged_name: &'static str,
    destination: PathBuf,
}

impl StagedTarget {
    fn stage(
        workspace_root: &Path,
        target: &SyncTarget,
        processors_root: &Path,
    ) -> Result<Self, SyncError> {
        let destination = workspace_root.join(target.destination);
        let destination_parent = destination
            .parent()
            .expect("sync target destination must have a parent");

        let staging_root = Builder::new()
            .prefix(".language-sync-")
            .tempdir_in(destination_parent)
            .map_err(|source| {
                SyncError::io("create temporary directory in", destination_parent, source)
            })?;
        let staged_path = staging_root.path().join(target.source_processor);
        fs::create_dir(&staged_path)
            .map_err(|source| SyncError::io("create directory", &staged_path, source))?;

        let source_path = processors_root
            .join(target.source_processor)
            .join("data/languages");
        let source = LanguageDir::new(&source_path);
        let staged = LanguageDir::new(&staged_path);
        let destination_dir = LanguageDir::new(&destination);

        for file in destination_dir.whitelist()? {
            staged.copy_file_from(&source, &file)?;
        }
        for file in staged.missing_sinc_includes()? {
            staged.copy_file_from(&source, &file)?;
        }

        Ok(Self {
            staging_root,
            staged_name: target.source_processor,
            destination,
        })
    }

    fn commit(self) -> Result<(), SyncError> {
        let staged = self.staging_root.path().join(self.staged_name);
        let backup = self.staging_root.path().join("backup");

        if self.destination.exists() {
            fs::rename(&self.destination, &backup)
                .map_err(|source| SyncError::rename_path(&self.destination, &backup, source))?;
        }

        if let Err(source) = fs::rename(&staged, &self.destination) {
            if backup.exists() {
                let _ = fs::rename(&backup, &self.destination);
            }
            return Err(SyncError::rename_path(&staged, &self.destination, source));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{LanguageDir, ReleaseTag, SyncJob, SYNC_TARGETS};

    fn create_source_tree(root: &Path) {
        for target in SYNC_TARGETS {
            let processor = target.source_processor;
            let source_directory = root
                .join("Ghidra/Processors")
                .join(processor)
                .join("data/languages");
            fs::create_dir_all(&source_directory).unwrap();
            fs::write(
                source_directory.join(format!("{processor}.slaspec")),
                format!("@include \"{processor}.sinc\"\n@include \"extra.sinc\"\n"),
            )
            .unwrap();
            fs::write(
                source_directory.join(format!("{processor}.sinc")),
                format!("source:{processor}.sinc"),
            )
            .unwrap();
            fs::write(source_directory.join("extra.sinc"), "source:extra.sinc").unwrap();
        }
    }

    fn create_workspace_tree(root: &Path) {
        for target in SYNC_TARGETS {
            let processor = target.source_processor;
            let destination_directory = root.join(target.destination);
            fs::create_dir_all(&destination_directory).unwrap();
            fs::write(
                destination_directory.join(format!("{processor}.slaspec")),
                "old slaspec",
            )
            .unwrap();
            fs::write(
                destination_directory.join(format!("{processor}.sinc")),
                "old sinc",
            )
            .unwrap();
        }
    }

    #[test]
    fn parses_latest_stable_release_tag() {
        let tags = "\
deadbeef refs/tags/Ghidra_11.4_build\n\
deadbeef refs/tags/Ghidra_12.0_build\n\
deadbeef refs/tags/Ghidra_12.0.4_build\n\
deadbeef refs/tags/Ghidra_12.1_RC1_build\n";

        let latest = ReleaseTag::pick_latest(tags);

        assert_eq!(latest.as_deref(), Some("Ghidra_12.0.4_build"));
    }

    #[test]
    fn rejects_non_stable_release_tags() {
        assert_eq!(ReleaseTag::parse_version("Ghidra_12.1_RC1_build"), None);
        assert_eq!(ReleaseTag::parse_version("nightly"), None);
    }

    #[test]
    fn syncs_from_local_directory_and_copies_required_sincs() {
        let root = tempfile::tempdir().unwrap();
        let workspace_root = root.path().join("workspace");
        let source_root = root.path().join("ghidra");

        create_workspace_tree(&workspace_root);
        create_source_tree(&source_root);

        SyncJob {
            workspace_root: &workspace_root,
        }
        .local(&source_root)
        .unwrap();

        for target in SYNC_TARGETS {
            let processor = target.source_processor;
            let destination_directory = workspace_root.join(target.destination);
            assert_eq!(
                fs::read_to_string(destination_directory.join(format!("{processor}.slaspec")))
                    .unwrap(),
                format!("@include \"{processor}.sinc\"\n@include \"extra.sinc\"\n"),
            );
            assert_eq!(
                fs::read_to_string(destination_directory.join(format!("{processor}.sinc")))
                    .unwrap(),
                format!("source:{processor}.sinc"),
            );
            assert_eq!(
                fs::read_to_string(destination_directory.join("extra.sinc")).unwrap(),
                "source:extra.sinc",
            );
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
            .join("x86.sinc");
        fs::remove_file(missing).unwrap();

        let error = SyncJob {
            workspace_root: &workspace_root,
        }
        .local(&source_root)
        .unwrap_err();

        assert!(matches!(
            error,
            crate::SyncError::MissingPath {
                kind: "source file",
                ..
            }
        ));

        for target in SYNC_TARGETS {
            let processor = target.source_processor;
            let destination_directory = workspace_root.join(target.destination);
            assert_eq!(
                fs::read_to_string(destination_directory.join(format!("{processor}.slaspec")))
                    .unwrap(),
                "old slaspec",
            );
        }
    }

    #[test]
    fn reads_current_directory_as_whitelist() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path();

        fs::write(directory.join("b.sinc"), "").unwrap();
        fs::write(directory.join("a.slaspec"), "").unwrap();
        fs::create_dir_all(directory.join("nested")).unwrap();

        let whitelist = LanguageDir::new(directory).whitelist().unwrap();

        assert_eq!(whitelist, vec!["a.slaspec", "b.sinc"]);
    }

    #[test]
    fn extracts_sinc_includes_from_slaspec() {
        let contents = r#"
@include "foo.sinc"
@include "foo.sinc"
@include "bar.pspec"
<external_name tool="gnu" name="not-a-file"/>
"#;

        let references = LanguageDir::extract_sinc_includes(contents);

        assert_eq!(references, vec!["foo.sinc"]);
    }

    #[test]
    fn finds_missing_sinc_includes_in_whitelisted_slaspecs() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path();

        fs::write(
            directory.join("root.slaspec"),
            "@include \"present.sinc\"\n@include \"missing.sinc\"\n@include \"other.pspec\"",
        )
        .unwrap();
        fs::write(
            directory.join("skip.sinc"),
            "@include \"nested-missing.sinc\"",
        )
        .unwrap();
        fs::write(directory.join("present.sinc"), "").unwrap();

        let missing = LanguageDir::new(directory).missing_sinc_includes().unwrap();

        assert_eq!(missing, vec!["missing.sinc"]);
    }
}
