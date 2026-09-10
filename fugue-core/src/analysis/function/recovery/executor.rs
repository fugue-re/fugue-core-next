use std::thread;

use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};

use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::FUNCTION_RECOVERY_ANALYSER;
use crate::analysis::function::recovery::analysis::FunctionRecoveryContext;
use crate::analysis::function::recovery::builder::{
    FunctionBuilder, FunctionCandidateOutcome, FunctionCandidateState,
};
use crate::engine::AnalysisContext;
use crate::ir::AddressWithContext;
use crate::lifter::InsnResolver;

pub(crate) struct FunctionCandidateBatch<'a> {
    candidates: Vec<AddressWithContext>,
    context: &'a FunctionRecoveryContext,
}

impl<'a> FunctionCandidateBatch<'a> {
    pub(crate) fn new(
        context: &'a FunctionRecoveryContext,
        candidates: Vec<AddressWithContext>,
    ) -> Self {
        Self {
            candidates,
            context,
        }
    }
}

#[derive(Default)]
pub(crate) struct FunctionRecoveryExecutor {
    pool: Option<ThreadPool>,
}

fn worker_count(
    analysis: &AnalysisContext<'_, '_>,
    builder: &FunctionBuilder,
    candidate_count: usize,
    worker_limit: usize,
) -> usize {
    if builder.pre_resolution_passes().can_analyse(analysis) {
        return 1;
    }

    thread::available_parallelism()
        .map_or(1, usize::from)
        .min(worker_limit)
        .min(candidate_count)
}

impl FunctionRecoveryExecutor {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn analyse_candidates(
        &mut self,
        analysis: &mut AnalysisContext<'_, '_>,
        builder: &mut FunctionBuilder,
        resolver: &mut Option<InsnResolver>,
        batch: FunctionCandidateBatch<'_>,
        mut on_outcome: impl FnMut(
            &mut AnalysisContext<'_, '_>,
            FunctionCandidateOutcome,
        ) -> Result<bool, AnalysisError>,
    ) -> Result<Vec<AddressWithContext>, AnalysisError> {
        let worker_limit = analysis.worker_limit();
        let FunctionCandidateBatch {
            candidates,
            context,
        } = batch;

        let workers = worker_count(analysis, builder, candidates.len(), worker_limit);
        if workers <= 1 {
            let mut candidates = candidates.into_iter();
            while let Some(candidate) = candidates.next() {
                let outcome = builder.analyse_candidate(analysis, context, resolver, candidate);
                if on_outcome(analysis, outcome)? {
                    return Ok(candidates.collect());
                }
            }
            return Ok(Vec::new());
        }

        self.configure_pool(workers)?;
        let pool = self
            .pool
            .as_ref()
            .expect("the parallel recovery pool must be configured");
        let config = *builder.config();
        let mut candidates = candidates.into_iter();

        loop {
            let mut tasks = candidates
                .by_ref()
                .take(workers)
                .map(|candidate| {
                    FunctionCandidateState::new(analysis.project.fork(), candidate, &config)
                })
                .collect::<Vec<_>>();
            if tasks.is_empty() {
                return Ok(Vec::new());
            }

            loop {
                let avoidance_baseline = builder.avoids();
                let arch = analysis.project.arch();
                pool.install(|| {
                    tasks.par_iter_mut().for_each_init(
                        || InsnResolver::new(arch),
                        |resolver, task| {
                            task.resolve(&config, context, resolver, avoidance_baseline);
                        },
                    );
                });

                let mut pending = false;
                for task in &mut tasks {
                    task.apply_post_structuring_passes(
                        analysis,
                        &config,
                        builder.post_structuring_passes_mut(),
                    );
                    pending |= !task.is_finished();
                }
                if !pending {
                    break;
                }
            }

            let mut tasks = tasks.into_iter();
            while let Some(task) = tasks.next() {
                analysis.project.merge(task.view());
                let outcome = task.finish();
                for range in outcome.avoids().ranges() {
                    builder.avoids_mut().insert_range(range);
                }
                if on_outcome(analysis, outcome)? {
                    let mut remaining = tasks
                        .map(FunctionCandidateState::into_candidate)
                        .collect::<Vec<_>>();
                    remaining.extend(candidates);
                    return Ok(remaining);
                }
            }
        }
    }

    fn configure_pool(&mut self, workers: usize) -> Result<(), AnalysisError> {
        if self
            .pool
            .as_ref()
            .is_some_and(|pool| pool.current_num_threads() == workers)
        {
            return Ok(());
        }

        self.pool = Some(
            ThreadPoolBuilder::new()
                .num_threads(workers)
                .thread_name(|index| format!("fugue-recovery-{index}"))
                .build()
                .map_err(|error| {
                    AnalysisError::pass_configuration_failed(FUNCTION_RECOVERY_ANALYSER, error)
                })?,
        );
        Ok(())
    }
}
