use std::fs::File;
use std::io::Read;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use anyhow::Error as AnyError;
use fugue_specs::PatternsWithContext;
use serde::{Deserialize, Serialize};
use serde_yaml::Error as YamlError;
use thiserror::Error;

use crate::analysis::function::recovery::analysis::FunctionDiscoveryContext;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::{AnalysisContext, ProjectView};
use crate::ir::{Address, AddressWithContext, RawAddress};
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

fn for_each_visible_byte_range(
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
        let Ok(view) =
            mapping_cache.contiguous_view_from(segments, Address::new(space_id, *range.start()))
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

    fn match_patterns_in_space(
        &self,
        project: &ProjectView<'_>,
        state: &mut FunctionDiscoveryContext,
        space_id: AddressSpaceId,
    ) {
        let segments = project.segments();
        let mut ranges = state.unclaimed_ranges(space_id);
        let Some(mut available) = ranges.next() else {
            tracing::debug!("no unclaimed ranges to analyse");
            return;
        };

        let arch = project.arch();
        let language = project.language();

        let mut mapping_cache = SegmentMappingCache::new();

        loop {
            tracing::debug!(
                "analysing available range {}-{}",
                available.start_address(),
                available.end_address()
            );
            for_each_visible_byte_range(
                segments,
                &mut mapping_cache,
                space_id,
                available.raw_range(),
                |range_in_space, bytes| {
                    for (range, context, confidence) in self
                        .patterns
                        .iter()
                        .flat_map(|patterns| patterns.matches(bytes))
                    {
                        let start = Address::new(space_id, *range_in_space.start() + range.start);
                        if arch.canonicalise_address(start).is_none() || ranges.is_avoided(start) {
                            continue;
                        }

                        let context = context
                            .variables()
                            .filter_map(|(var, val)| {
                                let bits = language.context_variable_by_name(var)?;
                                Some((bits, val))
                            })
                            .collect::<ContextSet>();

                        tracing::debug!(
                            "adding candidate at {start} with context {context:?} (confidence: {confidence})"
                        );

                        ranges.add_candidate(AddressWithContext::new_with(
                            start, context, confidence,
                        ));
                    }
                },
            );

            let Some(next) = ranges.next() else {
                break;
            };
            available = next;
        }
    }
}

impl AnalysisPass<FunctionDiscoveryContext> for FunctionRecoveryPatternMatcher {
    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        state: &mut FunctionDiscoveryContext,
    ) -> Result<(), AnalysisError> {
        let project = &context.project;
        let segments = project.segments();
        let spaces = segments.spaces();

        for space in spaces.map(|s| s.id()) {
            self.match_patterns_in_space(project, state, space);
        }

        Ok(())
    }
}
