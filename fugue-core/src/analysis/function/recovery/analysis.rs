use std::collections::{BTreeSet, VecDeque};
use std::time::Instant;

use crate::analysis::{AnalysisError, AnalysisPass};
use crate::ir::Address;
use crate::ir::traits::{FunctionTable, SymbolTable};
use crate::lifter::ContextSet;
use crate::project::{Project, ProjectMut};
use crate::storage::ProjectStorageProvider;
use crate::storage::project::InMemoryProvider;

use super::{
    FunctionBuilder, FunctionBuilderContext, FunctionRecoveryConfig, PartialFunctionWithContext,
    Translator,
};

pub struct FunctionRecovery<'a, P = InMemoryProvider>
where
    P: ProjectStorageProvider,
{
    candidates: VecDeque<(Address, ContextSet)>,
    builder: FunctionBuilder<'a, P>,
}

impl<'a, P> FunctionRecovery<'a, P>
where
    P: ProjectStorageProvider,
{
    pub fn new() -> Self {
        FunctionRecovery::new_with(FunctionRecoveryConfig::default())
    }

    pub fn new_with(config: FunctionRecoveryConfig) -> Self {
        FunctionRecovery {
            candidates: VecDeque::new(),
            builder: FunctionBuilder::new(config),
        }
    }

    pub fn add_candidate(&mut self, address: impl Into<Address>) {
        self.add_candidate_with_context(address, ContextSet::new());
    }

    pub fn add_candidate_with_context(&mut self, address: impl Into<Address>, context: ContextSet) {
        self.candidates.push_back((address.into(), context));
    }

    pub fn add_candidates(&mut self, addresses: impl IntoIterator<Item = impl Into<Address>>) {
        self.add_candidates_with_context(
            addresses
                .into_iter()
                .zip(std::iter::repeat(ContextSet::new())),
        );
    }

    pub fn add_candidates_with_context(
        &mut self,
        candidates: impl IntoIterator<Item = (impl Into<Address>, ContextSet)>,
    ) {
        self.candidates.extend(
            candidates
                .into_iter()
                .map(|(addr, context)| (addr.into(), context)),
        );
    }

    pub fn add_function_builder_initialisation_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, P, FunctionBuilderContext> + 'a,
    ) {
        self.builder.add_initialisation_pass(name, pass);
    }

    pub fn add_function_builder_post_lifting_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, P, PartialFunctionWithContext> + 'a,
    ) {
        self.builder.add_post_lifting_pass(name, pass);
    }
}

impl<'a, P> AnalysisPass<'a, P> for FunctionRecovery<'a, P>
where
    P: ProjectStorageProvider,
{
    fn analyse(&mut self, project: &mut Project<P>) -> Result<(), AnalysisError> {
        tracing::debug!("starting function recovery");

        let t = Instant::now();

        if let Some(entry) = project.entry() {
            tracing::debug!("entry point: {entry}");
            self.add_candidate(entry);
        }

        for (_, entry) in project
            .symbols()
            .iter_by_address()
            .filter(|(_, s)| s.is_function())
        {
            tracing::debug!("function: {} (name: {})", entry.address(), entry.symbol(),);
            self.add_candidate(entry.address());
        }

        let mut failures = BTreeSet::new();
        let mut functions = project.functions().addresses().collect::<BTreeSet<_>>();
        let mut translator = Translator::new(project);

        tracing::debug!("existing functions: {}", functions.len());

        while let Some((address, context)) = self.candidates.pop_front() {
            if !project.storage.segments.contains_segment(address) {
                tracing::trace!("skipping {address}: not mapped");
                continue;
            }

            if failures.contains(&address) {
                tracing::trace!("skipping {address}: already failed");
                continue;
            }

            if functions.contains(&address) {
                tracing::trace!("skipping {address}: already analysed");
                continue;
            }

            let function = match self
                .builder
                .analyse(project, &mut translator, address, context)
            {
                Ok(f) => f,
                Err(e) => {
                    failures.insert(address);
                    tracing::trace!("failed to analyse {address}: {e}");
                    continue;
                }
            };

            let ProjectMut {
                functions: ftable,
                blocks: cbtable,
                ..
            } = project.fields_mut();

            if let Err(e) = function.commit(ftable, cbtable) {
                tracing::debug!("failed to commit function at {address}: {e}");
                return Err(AnalysisError::pass_failed("function-recovery", e));
            }

            functions.insert(address);

            self.candidates.extend(
                self.builder
                    .global_targets()
                    .iter()
                    .filter(|(start, _)| !functions.contains(start) && !failures.contains(start))
                    .cloned(),
            );
        }

        let num_functions = functions.len();

        for f in functions {
            tracing::debug!("function: {f}");
        }

        let elapsed = t.elapsed();

        tracing::debug!(
            "function recovery completed in {}s ({}ms) with {num_functions} functions",
            elapsed.as_secs(),
            elapsed.as_millis(),
        );

        Ok(())
    }
}
