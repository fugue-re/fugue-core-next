use std::collections::{BTreeSet, VecDeque};
use std::time::Instant;

use crate::analysis::{AnalysisError, AnalysisPass};
use crate::ir::Address;
use crate::ir::traits::{FunctionTable, SymbolTable};
use crate::lifter::ContextSet;
use crate::project::Project;
use crate::storage::ProjectStorageProvider;
use crate::storage::project::InMemoryProvider;

use super::{
    FunctionBuilder, FunctionBuilderContext, FunctionRecoveryConfig, PartialFunctionWithContext,
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

            let mut function = match self.builder.analyse(project, address, context) {
                Ok(f) => f,
                Err(e) => {
                    failures.insert(address);
                    tracing::trace!("failed to analyse {address}: {e}");
                    continue;
                }
            };

            functions.insert(address);

            if let Err(e) = project.functions_mut().insert(address, move |id, _| {
                function.set_id(id);
                Ok(function)
            }) {
                tracing::debug!("failed to persist function at {address}: {e}");
                return Err(AnalysisError::pass_failed("function-recovery", e));
            }

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

#[cfg(test)]
mod test {
    use super::*;

    use crate::analysis::AnalysisPass;
    use crate::loader::Shellcode;
    use crate::project::InMemoryProject;

    #[test]
    fn test_control_flow_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut project = InMemoryProject::from_file("tests/ls.elf")?;
            let mut cfr = FunctionRecovery::new();

            cfr.add_candidate(0x4da0u64);
            cfr.add_candidate(0x6dd0u64);
            cfr.analyse(&mut project)?;

            Ok(())
        })
    }

    #[test]
    fn test_control_flow_recovery_overlap() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let shellcode = [
                0x55, 0x8B, 0xEC, 0x51, 0x51, 0x56, 0x8B, 0x75, 0x0C, 0x57, 0x33, 0xFF, 0x39, 0x3D,
                0x6C, 0x50, 0x40, 0x00, 0x75, 0x26, 0x56, 0xFF, 0x75, 0x08, 0x68, 0x18, 0x12, 0x40,
                0x00, 0xFF, 0x15, 0xF0, 0x10, 0x40, 0x00, 0x85, 0xC0, 0x74, 0x13, 0x68, 0xE0, 0x12,
                0x40, 0x00, 0xFF, 0x75, 0x08, 0xFF, 0x15, 0xEC, 0x10, 0x40, 0x00, 0x33, 0xC0, 0x40,
                0xEB, 0x43, 0x8D, 0x45, 0x0C, 0x50, 0x68, 0x28, 0x13, 0x40, 0x00, 0x68, 0x02, 0x00,
                0x00, 0x80, 0xFF, 0x15, 0x08, 0x10, 0x40, 0x00, 0x85, 0xC0, 0x75, 0x29, 0x8D, 0x45,
                0xFC, 0x50, 0xFF, 0x75, 0x08, 0x8D, 0x45, 0xF8, 0x50, 0x57, 0x57, 0xFF, 0x75, 0x0C,
                0x89, 0x75, 0xFC, 0xFF, 0x15, 0x00, 0x10, 0x40, 0x00, 0x85, 0xC0, 0x75, 0x03, 0x33,
                0xFF, 0x47, 0xFF, 0x75, 0x0C, 0xFF, 0x15, 0x24, 0x10, 0x40, 0x00, 0x8B, 0xC7, 0x5F,
                0x5E, 0xC9, 0xC2, 0x08, 0x00,
            ];

            let mut project =
                InMemoryProject::new(&Shellcode::new("x86:LE:64", 0x4EB14u64, &shellcode)?)?;
            let mut cfr = FunctionRecovery::new();

            cfr.add_candidate(0x4EB14u64);
            cfr.analyse(&mut project)?;

            Ok(())
        })
    }
}
