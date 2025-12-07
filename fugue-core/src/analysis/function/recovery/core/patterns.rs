use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use fugue_specs::PatternsWithContext;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::function::recovery::analysis::FunctionDiscoveryContext;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::project::Project;
use crate::storage::ProjectStorageProvider;

#[derive(Debug, Error)]
pub enum FunctionRecoveryPatternMatcherError {
    #[error("failed to parse patterns: {0}")]
    Parse(#[from] serde_saphyr::Error),
    #[error("failed to read patterns from {0}: {1}")]
    Io(PathBuf, anyhow::Error),
}

impl FunctionRecoveryPatternMatcherError {
    pub fn io<E>(path: impl Into<PathBuf>, err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Io(path.into(), err.into())
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub struct FunctionRecoveryPatternMatcher {
    patterns: Vec<PatternsWithContext>,
}

impl FunctionRecoveryPatternMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_patterns(&mut self, patterns: PatternsWithContext) {
        self.patterns.push(patterns);
    }

    pub fn add_patterns_from_reader(
        &mut self,
        reader: impl Read,
    ) -> Result<(), FunctionRecoveryPatternMatcherError> {
        let pats = serde_saphyr::from_reader::<_, PatternsWithContext>(reader)?;
        self.patterns.push(pats);
        Ok(())
    }

    pub fn add_patterns_from_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<(), FunctionRecoveryPatternMatcherError> {
        let path = path.as_ref();
        let reader =
            File::open(path).map_err(|e| FunctionRecoveryPatternMatcherError::io(path, e))?;
        self.add_patterns_from_reader(reader)
            .map_err(|e| FunctionRecoveryPatternMatcherError::io(path, e))
    }
}

impl<P> AnalysisPass<'_, P, FunctionDiscoveryContext> for FunctionRecoveryPatternMatcher
where
    P: ProjectStorageProvider,
{
    fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        state: &mut FunctionDiscoveryContext,
    ) -> Result<(), AnalysisError> {
        let gaps = state
            .gaps(project.functions(), project.blocks(), project.segments())
            .map_err(|e| AnalysisError::pass_failed("function-recovery-pattern-matcher", e))?;

        if gaps.is_empty() {
            return Ok(());
        }

        for gap in gaps.ranges() {
            // NOTE: we may overlaps segments; need to handle this case by splitting across them
            // that said, this is not really an issue--we will just split them.

            for pat in self.patterns.iter() {
                // TODO: apply the patterns
            }
        }

        Ok(())
    }
}
