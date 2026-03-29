use std::fs::File;
use std::io::Read;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use fugue_specs::PatternsWithContext;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::function::recovery::analysis::FunctionDiscoveryContext;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::ir::{Address, AddressWithContext};
use crate::lifter::ContextSet;
use crate::project::Project;
use crate::storage::segments::view::SegmentMappingView;
use crate::storage::{ProjectStorageProvider, SegmentStorage};

#[derive(Debug, Error)]
pub enum FunctionRecoveryPatternMatcherError {
    #[error("failed to read patterns from {0}: {1}")]
    Io(PathBuf, anyhow::Error),
    #[error("failed to parse patterns: {0}")]
    Parse(#[from] serde_yaml::Error),
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

    pub fn add_patterns_from_str(
        &mut self,
        s: &str,
    ) -> Result<(), FunctionRecoveryPatternMatcherError> {
        let pats = serde_yaml::from_str::<PatternsWithContext>(s)?;
        self.patterns.push(pats);
        Ok(())
    }

    pub fn add_patterns_from_reader(
        &mut self,
        reader: impl Read,
    ) -> Result<(), FunctionRecoveryPatternMatcherError> {
        let pats = serde_yaml::from_reader::<_, PatternsWithContext>(reader)?;
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

    fn for_each_segment<'a>(
        segments: &'a SegmentStorage,
        segm: &mut Option<SegmentMappingView<'a>>,
        gap: RangeInclusive<Address>,
        mut f: impl FnMut(RangeInclusive<Address>, &[u8]),
    ) {
        let current_segment = segm;
        let gap_end = *gap.end();

        let mut current_start = *gap.start();
        let calculate_end = |segm: &SegmentMappingView| -> Address {
            let segm_end = segm.last();
            if segm_end <= gap_end {
                segm_end
            } else {
                gap_end
            }
        };

        while current_start <= gap_end {
            let (range, segm) = if let Some(segm) = current_segment.as_ref()
                && segm.contains(current_start)
            {
                let match_end = calculate_end(segm);
                let range = current_start..=match_end;

                current_start = match_end + 1usize;

                (range, segm)
            } else {
                let Ok(segment) = segments.view_at(current_start) else {
                    break;
                };

                let match_end = calculate_end(&segment);
                let range = current_start..=match_end;

                current_start = match_end + 1usize;

                let segm = current_segment.insert(segment);

                (range, &*segm)
            };

            let size = 1usize + range.end().absolute_difference(range.start()) as usize;
            let Some(bytes) = segm.bytes_at(*range.start(), size) else {
                break;
            };

            f(range, &bytes);
        }
    }
}

impl<P> AnalysisPass<P, FunctionDiscoveryContext> for FunctionRecoveryPatternMatcher
where
    P: ProjectStorageProvider,
{
    fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        state: &mut FunctionDiscoveryContext,
    ) -> Result<(), AnalysisError> {
        let segments = project.segments();

        let gaps = state
            .gaps(project.functions(), project.blocks(), segments)
            .map_err(|e| AnalysisError::pass_failed("function-recovery-pattern-matcher", e))?;

        if gaps.is_empty() {
            tracing::debug!("no gaps to analyse");
            return Ok(());
        }

        let arch = project.arch();
        let language = project.language();

        let mut current_segm = None::<SegmentMappingView<'_>>;

        for gap in gaps.ranges() {
            tracing::debug!("analysing gap {}-{}", gap.start(), gap.end());
            Self::for_each_segment(segments, &mut current_segm, gap, |gap, bytes| {
                for pat in self.patterns.iter() {
                    for (range, ctx, confidence) in pat.matches(bytes) {
                        let start = *gap.start() + range.start;

                        if arch.canonicalise_address(start).is_none() {
                            continue;
                        }

                        if state.avoids().contains(start) || state.failures().contains(&start) {
                            continue;
                        }

                        let ctx = ctx
                            .variables()
                            .filter_map(|(var, val)| {
                                let bits = language.context_variable_by_name(var)?;
                                Some((bits, val))
                            })
                            .collect::<ContextSet>();

                        tracing::debug!(
                            "adding candidate at {start} with context {ctx:?} (confidence: {confidence})"
                        );

                        state.add_candidate(AddressWithContext::new_with(start, ctx, confidence));
                    }
                }
            });
        }

        Ok(())
    }
}
