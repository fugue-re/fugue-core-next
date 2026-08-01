use std::fs::File;
use std::io::Read;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use anyhow::Error as AnyError;
use fugue_specs::PatternsWithContext;
use serde::{Deserialize, Serialize};
use serde_yaml::Error as YamlError;
use smallvec::SmallVec;
use thiserror::Error;

use crate::analysis::function::recovery::analysis::FunctionDiscoveryContext;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::ProjectView;
use crate::ir::{Address, AddressRange, AddressWithContext, RawAddress};
use crate::lifter::ContextSet;
use crate::storage::{AddressSpaceId, SegmentMappingCache, SegmentMappingView, SegmentStorage};

#[derive(Debug, Error)]
pub enum FunctionRecoveryPatternMatcherError {
    #[error("failed to read patterns from {0}: {1}")]
    Io(PathBuf, AnyError),
    #[error("failed to parse patterns: {0}")]
    Parse(#[from] YamlError),
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

    // NOTE: all segments are in the same space
    fn for_each_segment(
        segments: &SegmentStorage,
        mapping_cache: &mut SegmentMappingCache,
        space_id: AddressSpaceId,
        gap: RangeInclusive<RawAddress>,
        mut f: impl FnMut(RangeInclusive<RawAddress>, &[u8]),
    ) {
        let gap_end = *gap.end();
        let mut current_start = *gap.start();

        let calculate_end = |view: &SegmentMappingView| -> RawAddress {
            let view_end = view.last().raw_address();
            if view_end <= gap_end {
                view_end
            } else {
                gap_end
            }
        };

        while current_start <= gap_end {
            let current_meta = Address::new(space_id, current_start);
            let Some(view) = mapping_cache.view_containing(segments, current_meta) else {
                break;
            };

            let match_end = calculate_end(&view);
            let range = current_start..=match_end;
            let next_start = match_end.checked_add(1usize);

            let size = 1usize + range.end().absolute_difference(range.start()) as usize;
            let Ok(view) = mapping_cache
                .contiguous_view_from(segments, Address::new(space_id, *range.start()))
            else {
                if let Some(next_start) = next_start {
                    current_start = next_start;
                    continue;
                }
                break;
            };
            let bytes = view
                .as_contiguous()
                .expect("contiguous mapping view must contain bytes");
            let Some(bytes) = bytes.get(..size) else {
                break;
            };

            f(range, bytes);
            let Some(next_start) = next_start else {
                break;
            };
            current_start = next_start;
        }
    }

    fn analyse_space(
        &mut self,
        project: &ProjectView<'_>,
        state: &mut FunctionDiscoveryContext,
        space_id: AddressSpaceId,
    ) -> Result<(), AnalysisError> {
        let segments = project.segments();
        let available = state
            .available_ranges(space_id)
            .collect::<SmallVec<[_; 4]>>();

        if available.is_empty() {
            tracing::debug!("no gaps to analyse");
            return Ok(());
        }

        let arch = project.arch();
        let language = project.language();

        let mut mapping_cache = SegmentMappingCache::new();

        for available in available {
            tracing::debug!(
                "analysing available range {}-{}",
                available.start(),
                available.end()
            );
            Self::for_each_segment(
                segments,
                &mut mapping_cache,
                space_id,
                available,
                |range_in_space, bytes| {
                    for pat in self.patterns.iter() {
                        for (range, ctx, confidence) in pat.matches(bytes) {
                            let start =
                                Address::new(space_id, *range_in_space.start() + range.start);
                            let Some(matched) =
                                AddressRange::from_size(start, (range.end - range.start) as u64)
                            else {
                                continue;
                            };

                            if state.covered().intersects_range(&matched)
                                || arch.canonicalise_address(start).is_none()
                            {
                                continue;
                            }

                            if state.avoids().contains(start) {
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

                            state.add_candidate(AddressWithContext::new_with(
                                start, ctx, confidence,
                            ));
                        }
                    }
                },
            );
        }

        Ok(())
    }
}

impl AnalysisPass<FunctionDiscoveryContext> for FunctionRecoveryPatternMatcher {
    fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        state: &mut FunctionDiscoveryContext,
    ) -> Result<(), AnalysisError> {
        let segments = project.segments();
        let spaces = segments.spaces();

        for space in spaces.map(|s| s.id()) {
            self.analyse_space(project, state, space)?;
        }

        Ok(())
    }
}
