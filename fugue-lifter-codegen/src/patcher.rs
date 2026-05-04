use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::{fs, io};

use diffy::{ApplyError, ParsePatchError, Patch};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum PatcherError {
    #[error("cannot read patch directory `{path}`: {source}")]
    PatchDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot read patch file `{path}`: {source}")]
    ReadPatch {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("patch `{path}` is not valid UTF-8")]
    PatchEncoding { path: PathBuf },
    #[error("patch `{path}` (segment {segment}) is malformed: {source}")]
    Parse {
        path: PathBuf,
        segment: usize,
        #[source]
        source: ParsePatchError,
    },
    #[error("patch `{path}` (segment {segment}) has no `+++` target header")]
    MissingTarget { path: PathBuf, segment: usize },
    #[error(
        "patch `{path}` (segment {segment}) targets `{target}`, which escapes the source root"
    )]
    EscapingTarget {
        path: PathBuf,
        segment: usize,
        target: String,
    },
    #[error(
        "patch `{path}` (segment {segment}) targets `{target}`, which is not present in the source tree"
    )]
    UnknownTarget {
        path: PathBuf,
        segment: usize,
        target: String,
    },
    #[error("patch `{path}` (segment {segment}) failed to apply to `{target}`: {source}")]
    Apply {
        path: PathBuf,
        segment: usize,
        target: String,
        #[source]
        source: ApplyError,
    },
    #[error("cannot mirror source tree from `{src}` to `{dst}`: {source}")]
    Mirror {
        src: PathBuf,
        dst: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot {action} `{path}`: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Default, Clone)]
pub struct PatchSet {
    files: Vec<PatchFile>,
}

#[derive(Debug, Clone)]
struct PatchFile {
    path: PathBuf,
    content: String,
}

impl PatchSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Self, PatcherError> {
        let dir = dir.as_ref();
        if !dir.exists() {
            return Ok(Self::default());
        }
        let mut entries = Vec::new();
        let read = fs::read_dir(dir).map_err(|source| PatcherError::PatchDir {
            path: dir.to_path_buf(),
            source,
        })?;
        for entry in read {
            let entry = entry.map_err(|source| PatcherError::PatchDir {
                path: dir.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            match path.extension().and_then(OsStr::to_str) {
                Some("patch") | Some("diff") => entries.push(path),
                _ => continue,
            }
        }
        entries.sort();

        let mut files = Vec::with_capacity(entries.len());
        for path in entries {
            let content = fs::read_to_string(&path).map_err(|source| {
                if matches!(source.kind(), io::ErrorKind::InvalidData) {
                    PatcherError::PatchEncoding { path: path.clone() }
                } else {
                    PatcherError::ReadPatch {
                        path: path.clone(),
                        source,
                    }
                }
            })?;
            files.push(PatchFile { path, content });
        }
        Ok(Self { files })
    }

    pub fn extend(&mut self, other: PatchSet) {
        self.files.extend(other.files);
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }
}

pub fn materialise(
    src: impl AsRef<Path>,
    dst: impl AsRef<Path>,
    patches: &PatchSet,
) -> Result<PathBuf, PatcherError> {
    let src = src.as_ref();
    let dst = dst.as_ref();

    if dst.exists() {
        fs::remove_dir_all(dst).map_err(|source| PatcherError::Io {
            action: "remove existing destination",
            path: dst.to_path_buf(),
            source,
        })?;
    }
    mirror_tree(src, dst)?;

    for file in &patches.files {
        apply_patch_file(dst, file)?;
    }

    Ok(dst.to_path_buf())
}

fn mirror_tree(src: &Path, dst: &Path) -> Result<(), PatcherError> {
    let mirror_err = |source: io::Error| PatcherError::Mirror {
        src: src.to_path_buf(),
        dst: dst.to_path_buf(),
        source,
    };

    fs::create_dir_all(dst).map_err(mirror_err)?;

    for entry in WalkDir::new(src).follow_links(false) {
        let entry = entry.map_err(|err| {
            mirror_err(
                err.into_io_error()
                    .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "walkdir error")),
            )
        })?;
        let from = entry.path();
        let rel = from
            .strip_prefix(src)
            .expect("walkdir yields prefixed paths");
        if rel.as_os_str().is_empty() {
            continue;
        }
        let to = dst.join(rel);

        let file_type = entry.file_type();
        if file_type.is_dir() {
            fs::create_dir_all(&to).map_err(|source| PatcherError::Io {
                action: "create directory",
                path: to.clone(),
                source,
            })?;
        } else if file_type.is_file() {
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent).map_err(|source| PatcherError::Io {
                    action: "create directory",
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            fs::copy(from, &to).map_err(|source| PatcherError::Io {
                action: "copy file",
                path: to.clone(),
                source,
            })?;
        }
    }

    Ok(())
}

fn apply_patch_file(dst: &Path, file: &PatchFile) -> Result<(), PatcherError> {
    for (segment_index, segment) in split_into_segments(&file.content).enumerate() {
        if segment.trim().is_empty() {
            continue;
        }
        let segment_id = segment_index + 1;

        let patch = Patch::from_str(segment).map_err(|source| PatcherError::Parse {
            path: file.path.clone(),
            segment: segment_id,
            source,
        })?;

        let target_rel = patch
            .modified()
            .or_else(|| patch.original())
            .ok_or_else(|| PatcherError::MissingTarget {
                path: file.path.clone(),
                segment: segment_id,
            })?;
        let target_rel = strip_diff_prefix(target_rel);
        let target_rel_path = Path::new(target_rel);
        if target_rel_path.is_absolute()
            || target_rel_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(PatcherError::EscapingTarget {
                path: file.path.clone(),
                segment: segment_id,
                target: target_rel.to_owned(),
            });
        }

        let target_abs = dst.join(target_rel_path);
        if !target_abs.is_file() {
            return Err(PatcherError::UnknownTarget {
                path: file.path.clone(),
                segment: segment_id,
                target: target_rel.to_owned(),
            });
        }

        let original = fs::read_to_string(&target_abs).map_err(|source| PatcherError::Io {
            action: "read patch target",
            path: target_abs.clone(),
            source,
        })?;
        let updated = diffy::apply(&original, &patch).map_err(|source| PatcherError::Apply {
            path: file.path.clone(),
            segment: segment_id,
            target: target_rel.to_owned(),
            source,
        })?;
        fs::write(&target_abs, updated).map_err(|source| PatcherError::Io {
            action: "write patched file",
            path: target_abs,
            source,
        })?;
    }

    Ok(())
}

fn split_into_segments(content: &str) -> impl Iterator<Item = &str> {
    let markers = content
        .match_indices("\ndiff --git ")
        .map(|(idx, _)| idx + 1)
        .collect::<Vec<usize>>();

    let starts = if content.starts_with("diff --git ") {
        std::iter::once(0)
            .chain(markers.iter().copied())
            .collect::<Vec<usize>>()
    } else if markers.is_empty() {
        vec![0]
    } else {
        markers.clone()
    };

    let ends = starts
        .iter()
        .skip(1)
        .copied()
        .chain(std::iter::once(content.len()))
        .collect::<Vec<usize>>();

    starts
        .into_iter()
        .zip(ends)
        .map(move |(start, end)| &content[start..end])
}

fn strip_diff_prefix(name: &str) -> &str {
    let trimmed_tail = name.split('\t').next().unwrap_or(name).trim();
    trimmed_tail
        .strip_prefix("a/")
        .or_else(|| trimmed_tail.strip_prefix("b/"))
        .unwrap_or(trimmed_tail)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn empty_patch_dir_is_a_pure_copy() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();
        write(src.path(), "a/foo.txt", "hello\n");
        write(src.path(), "b/bar.txt", "world\n");

        let dst_path = dst.path().join("out");
        let patches = PatchSet::new();
        let result = materialise(src.path(), &dst_path, &patches).unwrap();
        assert_eq!(result, dst_path);
        assert_eq!(
            fs::read_to_string(dst_path.join("a/foo.txt")).unwrap(),
            "hello\n"
        );
        assert_eq!(
            fs::read_to_string(dst_path.join("b/bar.txt")).unwrap(),
            "world\n"
        );
    }

    #[test]
    fn applies_single_hunk() {
        let src = TempDir::new().unwrap();
        let patches_dir = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        write(
            src.path(),
            "ARM/ARMinstructions.sinc",
            "alpha\nbeta\ngamma\n",
        );
        write(
            patches_dir.path(),
            "0001-rename.patch",
            concat!(
                "--- a/ARM/ARMinstructions.sinc\n",
                "+++ b/ARM/ARMinstructions.sinc\n",
                "@@ -1,3 +1,3 @@\n",
                " alpha\n",
                "-beta\n",
                "+BETA\n",
                " gamma\n",
            ),
        );

        let patches = PatchSet::load_dir(patches_dir.path()).unwrap();
        assert_eq!(patches.len(), 1);

        let dst_path = dst.path().join("out");
        materialise(src.path(), &dst_path, &patches).unwrap();
        assert_eq!(
            fs::read_to_string(dst_path.join("ARM/ARMinstructions.sinc")).unwrap(),
            "alpha\nBETA\ngamma\n"
        );
    }

    #[test]
    fn rejects_nonmatching_context() {
        let src = TempDir::new().unwrap();
        let patches_dir = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        write(src.path(), "ARM/file.sinc", "one\ntwo\nthree\n");
        write(
            patches_dir.path(),
            "0001-bad.patch",
            concat!(
                "--- a/ARM/file.sinc\n",
                "+++ b/ARM/file.sinc\n",
                "@@ -1,3 +1,3 @@\n",
                " one\n",
                "-DOES_NOT_EXIST\n",
                "+X\n",
                " three\n",
            ),
        );

        let patches = PatchSet::load_dir(patches_dir.path()).unwrap();
        let err = materialise(src.path(), dst.path().join("out"), &patches).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("0001-bad.patch"), "{msg}");
        assert!(msg.contains("ARM/file.sinc"), "{msg}");
    }

    #[test]
    fn applies_patches_in_filename_order() {
        let src = TempDir::new().unwrap();
        let patches_dir = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        write(src.path(), "f.txt", "v0\n");
        write(
            patches_dir.path(),
            "0002-second.patch",
            "--- a/f.txt\n+++ b/f.txt\n@@ -1 +1 @@\n-v1\n+v2\n",
        );
        write(
            patches_dir.path(),
            "0001-first.patch",
            "--- a/f.txt\n+++ b/f.txt\n@@ -1 +1 @@\n-v0\n+v1\n",
        );

        let patches = PatchSet::load_dir(patches_dir.path()).unwrap();
        let dst_path = dst.path().join("out");
        materialise(src.path(), &dst_path, &patches).unwrap();
        assert_eq!(fs::read_to_string(dst_path.join("f.txt")).unwrap(), "v2\n");
    }

    #[test]
    fn rejects_target_outside_source_root() {
        let src = TempDir::new().unwrap();
        let patches_dir = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        write(src.path(), "f.txt", "x\n");
        write(
            patches_dir.path(),
            "0001-evil.patch",
            "--- a/../f.txt\n+++ b/../f.txt\n@@ -1 +1 @@\n-x\n+y\n",
        );

        let patches = PatchSet::load_dir(patches_dir.path()).unwrap();
        let err = materialise(src.path(), dst.path().join("out"), &patches).unwrap_err();
        assert!(matches!(err, PatcherError::EscapingTarget { .. }));
    }

    #[test]
    fn split_handles_multifile_git_diff() {
        let combined = "diff --git a/foo b/foo\n\
                        --- a/foo\n+++ b/foo\n@@ -1 +1 @@\n-a\n+b\n\
                        diff --git a/bar b/bar\n\
                        --- a/bar\n+++ b/bar\n@@ -1 +1 @@\n-c\n+d\n";
        let segments: Vec<_> = split_into_segments(combined).collect();
        assert_eq!(segments.len(), 2);
        assert!(segments[0].starts_with("diff --git a/foo"));
        assert!(segments[1].starts_with("diff --git a/bar"));
    }
}
