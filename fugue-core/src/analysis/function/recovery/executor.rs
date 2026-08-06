use std::thread;

use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};

use super::builder::{FunctionBuilderInputs, FunctionCandidateOutcome, FunctionCandidateState};
use super::{FUNCTION_RECOVERY_ANALYSER, FunctionBuilder};
use crate::analysis::AnalysisError;
use crate::analysis::control::CancellationToken;
use crate::engine::ProjectView;
use crate::ir::AddressWithContext;
use crate::lifter::InsnResolver;

pub(crate) struct FunctionCandidateBatch<'a, 'p> {
    candidates: Vec<AddressWithContext>,
    inputs: FunctionBuilderInputs<'a>,
    project: &'a ProjectView<'p>,
    token: &'a CancellationToken,
    worker_limit: usize,
}

impl<'a, 'p> FunctionCandidateBatch<'a, 'p> {
    pub(crate) fn new(
        project: &'a ProjectView<'p>,
        inputs: FunctionBuilderInputs<'a>,
        candidates: Vec<AddressWithContext>,
        token: &'a CancellationToken,
        worker_limit: usize,
    ) -> Self {
        Self {
            candidates,
            inputs,
            project,
            token,
            worker_limit,
        }
    }
}

#[derive(Default)]
pub(crate) struct FunctionRecoveryExecutor {
    pool: Option<ThreadPool>,
}

impl FunctionRecoveryExecutor {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn analyse_candidates(
        &mut self,
        builder: &mut FunctionBuilder,
        resolver: &mut Option<InsnResolver>,
        batch: FunctionCandidateBatch<'_, '_>,
        mut on_outcome: impl FnMut(FunctionCandidateOutcome) -> Result<bool, AnalysisError>,
    ) -> Result<Vec<AddressWithContext>, AnalysisError> {
        let FunctionCandidateBatch {
            candidates,
            inputs,
            project,
            token,
            worker_limit,
        } = batch;
        let workers = Self::worker_count(builder, candidates.len(), worker_limit);
        if workers <= 1 {
            let mut candidates = candidates.into_iter();
            while let Some(candidate) = candidates.next() {
                let outcome =
                    builder.analyse_candidate(project, inputs, resolver, candidate, token);
                if on_outcome(outcome)? {
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
        let arch = project.arch();
        let config = *builder.config();
        let mut candidates = candidates.into_iter();

        loop {
            let mut tasks = candidates
                .by_ref()
                .take(workers)
                .map(|candidate| FunctionCandidateState::new(project.fork(), candidate, &config))
                .collect::<Vec<_>>();
            if tasks.is_empty() {
                return Ok(Vec::new());
            }

            loop {
                let avoidance_baseline = builder.avoids();
                pool.install(|| {
                    tasks.par_iter_mut().for_each_init(
                        || InsnResolver::new(arch),
                        |resolver, task| {
                            task.resolve(&config, inputs, token, resolver, avoidance_baseline);
                        },
                    );
                });

                let mut pending = false;
                for task in &mut tasks {
                    task.run_post_structuring(
                        &config,
                        builder.post_structuring_passes_mut(),
                        token,
                    );
                    pending |= !task.is_complete();
                }
                if !pending {
                    break;
                }
            }

            let mut tasks = tasks.into_iter();
            while let Some(task) = tasks.next() {
                let (reads, outcome) = task.finish();
                project.merge_reads(&reads);
                for range in outcome.avoids().ranges() {
                    builder.avoids_mut().insert_range(range);
                }
                if on_outcome(outcome)? {
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

    fn worker_count(
        builder: &FunctionBuilder,
        candidate_count: usize,
        worker_limit: usize,
    ) -> usize {
        if !builder.initialisation_passes().is_empty() {
            return 1;
        }

        thread::available_parallelism()
            .map_or(1, usize::from)
            .min(worker_limit)
            .min(candidate_count)
    }
}
