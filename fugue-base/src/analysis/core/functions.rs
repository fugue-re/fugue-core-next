use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use itertools::Itertools;
use thiserror::Error;

use crate::analysis::{AnalysisError, AnalysisGroup, AnalysisPass};
use crate::entities::flow_graph::{FlowKind, FlowTarget};
use crate::lifter::{ContextSet, LifterExt as _};
use crate::project::Project;
use crate::storage::StorageProvider;
use crate::types::Address;

pub struct FunctionRecoveryConfig {
    pub max_blocks: usize,
}

impl Default for FunctionRecoveryConfig {
    fn default() -> Self {
        FunctionRecoveryConfig {
            max_blocks: 0x10000,
        }
    }
}

pub struct FunctionRecovery<'a> {
    config: FunctionRecoveryConfig,
    candidates: VecDeque<(Address, ContextSet)>,
    builder: FunctionBuilder<'a>,
}

pub struct FunctionBuilderContext {
    entry: Address,
    candidates: VecDeque<(Address, ContextSet)>,
    contexts: BTreeMap<Address, ContextSet>,
    local_targets: BTreeSet<FlowTarget>,
    global_targets: BTreeSet<(Address, ContextSet)>,
}

pub struct FunctionBuilder<'a> {
    // The context of the function being built.
    context: FunctionBuilderContext,
    // These passes run once per function prior to the main lifting loop.
    initialisation_passes: AnalysisGroup<'a, FunctionBuilderContext>,
    // These passes run each iteration of the main lifting loop after all candidates within the
    // pass have been lifted and the function's control-flow has been structured based on the
    // identified blocks and flows.
    post_lifting_passes: AnalysisGroup<'a, FunctionBuilderContext>,
}

#[derive(Debug, Error)]
pub enum FunctionBuilderError {
    #[error("initialisation pass failed: {0}")]
    InitialisationPass(AnalysisError),
    #[error("post-lifting pass failed: {0}")]
    PostLiftingPass(AnalysisError),
    #[error("failed to lift any instructions")]
    NoInstructions,
}

impl<'a> FunctionRecovery<'a> {
    pub fn new() -> Self {
        FunctionRecovery::new_with(FunctionRecoveryConfig::default())
    }

    pub fn new_with(config: FunctionRecoveryConfig) -> Self {
        FunctionRecovery {
            config,
            candidates: VecDeque::new(),
            builder: FunctionBuilder::new(),
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
}

impl<'a> AnalysisPass<'a> for FunctionRecovery<'a> {
    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        if let Some(entry) = project.entry() {
            tracing::debug!("entry point: {entry}");
            self.add_candidate(entry);
        }

        for symbol in project.iter_local_symbols().filter(|s| s.is_function()) {
            tracing::debug!(
                "local function: {} (name: {:?})",
                symbol.address(),
                symbol.symbol()
            );
            self.add_candidate(symbol.address());
        }

        for symbol in project.iter_extern_symbols().filter(|s| s.is_function()) {
            tracing::debug!(
                "external function: {} (name: {:?})",
                symbol.address(),
                symbol.symbol()
            );
            self.add_candidate(symbol.address());
        }

        let mut functions = BTreeSet::new();
        let mut failures = BTreeSet::new();

        while let Some((address, context)) = self.candidates.pop_front() {
            if !project.storage.contains_segment(address) {
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

            if let Err(e) = self.builder.analyse(project, address, context) {
                failures.insert(address);
                tracing::debug!("failed to analyse {address}: {e}");
                continue;
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

        Ok(())
    }
}

impl<'a> FunctionBuilder<'a> {
    pub fn new() -> Self {
        FunctionBuilder {
            context: FunctionBuilderContext::new(),
            initialisation_passes: AnalysisGroup::new(),
            post_lifting_passes: AnalysisGroup::new(),
        }
    }

    pub fn initialisation_passes(&self) -> &AnalysisGroup<'a, FunctionBuilderContext> {
        &self.initialisation_passes
    }

    pub fn initialisation_passes_mut(&mut self) -> &mut AnalysisGroup<'a, FunctionBuilderContext> {
        &mut self.initialisation_passes
    }

    pub fn post_lifting_passes(&self) -> &AnalysisGroup<'a, FunctionBuilderContext> {
        &self.post_lifting_passes
    }

    pub fn post_lifting_passes_mut(&mut self) -> &mut AnalysisGroup<'a, FunctionBuilderContext> {
        &mut self.post_lifting_passes
    }

    pub fn context(&self) -> &FunctionBuilderContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut FunctionBuilderContext {
        &mut self.context
    }

    pub fn add_initialisation_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, FunctionBuilderContext> + 'a,
    ) {
        self.initialisation_passes.add_pass(name, pass);
    }

    pub fn add_post_lifting_pass(
        &mut self,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, FunctionBuilderContext> + 'a,
    ) {
        self.post_lifting_passes.add_pass(name, pass);
    }

    pub fn analyse(
        &mut self,
        project: &mut Project,
        address: impl Into<Address>,
        context: ContextSet,
    ) -> Result<(), FunctionBuilderError> {
        self.context.analyse(
            project,
            address,
            context,
            &mut self.initialisation_passes,
            &mut self.post_lifting_passes,
        )
    }

    pub fn local_targets(&self) -> &BTreeSet<FlowTarget> {
        &self.context.local_targets
    }

    pub fn global_targets(&self) -> &BTreeSet<(Address, ContextSet)> {
        &self.context.global_targets
    }
}

impl FunctionBuilderContext {
    pub fn new() -> Self {
        Self {
            entry: Address::zero(),
            candidates: VecDeque::new(),
            contexts: BTreeMap::new(),
            local_targets: BTreeSet::new(),
            global_targets: BTreeSet::new(),
        }
    }

    pub fn entry(&self) -> Address {
        self.entry
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

    pub fn add_local_target(
        &mut self,
        from: impl Into<Address>,
        to: impl Into<Address>,
        kind: FlowKind,
    ) {
        self.local_targets
            .insert(FlowTarget::new(from.into(), to.into(), kind));
    }

    pub fn clear(&mut self) {
        self.entry = Address::zero();
        self.candidates.clear();
        self.contexts.clear();
        self.local_targets.clear();
        self.global_targets.clear();
    }

    pub fn analyse(
        &mut self,
        project: &mut Project,
        address: impl Into<Address>,
        context: ContextSet,
        initialisation_passes: &mut AnalysisGroup<'_, FunctionBuilderContext>,
        post_lifting_passes: &mut AnalysisGroup<'_, FunctionBuilderContext>,
    ) -> Result<(), FunctionBuilderError> {
        // We have three main stages:
        //
        // 1. We first initialise the function builder with the entry point and the context
        //    of the entry block.
        // 2. We enter the main loop where we lift instructions block by block, and add newly
        //    discovered blocks (and edges) to the candidates queue.
        // 3. We structure the blocks into a basic function-like structure; we use this
        //    structure as input to resolve jump tables, indirect jumps, etc. this part of
        //    the analysis provides new candidates and new edges.
        //
        // Stage 1 and 3 are hookable; we may register analysis passes to be run prior to the
        // main loop and after each block discovery pass has completed within the main loop.
        //
        // By default these passes are added via `add_XXX_pass` methods during `FunctionRecovery`
        // initialisation.

        let candidate = address.into();

        tracing::debug!("exploring from {candidate}");

        self.clear();
        self.entry = candidate;

        self.candidates.push_back((candidate, context));

        // Run the initialisation passes
        initialisation_passes
            .analyse_with(project, self)
            .map_err(FunctionBuilderError::InitialisationPass)?;

        let mut insns = BTreeMap::<Address, _>::new();
        let mut bytes = [0u8; 32];

        loop {
            // This is the stage where we build blocks by collecting instructions and marking them.
            'outer: while let Some((block, mut context)) = self.candidates.pop_front() {
                // This ensures correct alignment, to address is correctly wrapped with respect to
                // the address space, and also extracts context updates indicated by the address,
                // e.g., if we are in Thumb context or not for ARM.
                let Some((block, ncontext)) = project.arch.canonicalise_address(block) else {
                    tracing::trace!("skipping {block}: not a viable block start address");
                    continue 'outer;
                };

                if !project.storage.contains_segment(block) {
                    tracing::trace!("skipping {block}: not mapped");
                    continue 'outer;
                }

                if insns.contains_key(&block) {
                    continue;
                }

                let mut offset = 0usize;

                // Merge the context updates with the specified context taking precedence.
                context.merge(ncontext);

                // Applies the context updates to the lifter context.
                context.apply(block, project.lifter.context_mut());

                // Save the context so we can associate it with a block later.
                self.contexts.insert(block, context);

                '_inner: loop {
                    let address = block + offset;

                    tracing::debug!("lifting at {address}");

                    // If we've already disassembled this instruction select the next candidate,
                    // otherwise get the entry ready for update.
                    let Entry::Vacant(entry) = insns.entry(address) else {
                        continue 'outer;
                    };

                    let Ok(size) = project.storage.read_bytes(address, &mut bytes) else {
                        tracing::trace!("skipping {address}: not mapped");
                        continue 'outer;
                    };

                    tracing::debug!("lifting {address}: {:?} ({size})", bytes);

                    let bytes = &bytes[..size];

                    match project.lifter.lift_insn(address, bytes) {
                        Ok(insn) => {
                            let insn = entry.insert(insn);

                            tracing::trace!("{address}: {:?}", insn.properties());

                            // Explicit control-flow
                            if insn.is_flow() {
                                // We're done with this block; we schedule the next bit of work

                                // These targets are what we can statically compute by scanning
                                // the instruction's PCode branch operations--we will miss things
                                // like PC relative jumps.
                                for (target, kind, addr) in insn.iter_targets() {
                                    let Some((addr, context)) =
                                        project.arch.canonicalise_address(addr)
                                    else {
                                        continue;
                                    };

                                    if kind.is_local() {
                                        let Some(target) =
                                            FlowTarget::from_insn_target(insn, target, addr)
                                        else {
                                            continue;
                                        };

                                        if self.local_targets.insert(target) {
                                            self.candidates.push_back((addr, context));
                                        }
                                    } else {
                                        self.global_targets.insert((addr, context));
                                    }
                                }

                                continue 'outer;
                            }

                            // Implicit control-flow (it is a halt, etc.)
                            if !insn.has_fall() {
                                // we're done with this block
                                continue 'outer;
                            }

                            offset += insn.len();
                        }
                        Err(e) => {
                            // flows into bad data??
                            tracing::debug!("skipping {address}; lifting failed: {e}");
                            continue 'outer;
                        }
                    }
                }
            }

            if insns.is_empty() {
                tracing::debug!("no instructions lifted; invalid function");
                return Err(FunctionBuilderError::NoInstructions);
            }

            tracing::debug!("{:?}", self.local_targets);

            // Structure the blocks
            let iinsns = &mut itertools::put_back(insns.iter());

            // Valid contexts contain all cut points
            let mut iblocks = self
                .contexts
                .iter()
                .filter_map(|(addr, _context)| {
                    if insns.contains_key(addr) {
                        Some(*addr)
                    } else {
                        None
                    }
                })
                .skip(1)
                .chain(std::iter::once(Address::MAX));

            let mut blocks = Vec::new();

            while let Some(next_block_start) = iblocks.next() {
                blocks.push(
                    iinsns
                        .peeking_take_while(|(start, _)| **start < next_block_start)
                        .collect::<Vec<_>>(),
                );
            }

            for block in blocks {
                tracing::debug!("blk@{}", block[0].0);
                for (addr, insn) in block {
                    tracing::debug!("{addr}: {}", insn.display(project.language));
                }
            }

            // Run the post-lifting passes
            let num_local_targets = self.local_targets.len();

            post_lifting_passes
                .analyse_with(project, self)
                .map_err(FunctionBuilderError::PostLiftingPass)?;

            if self.candidates.is_empty() && self.local_targets.len() == num_local_targets {
                // No new candidates were added, and no new local targets were discovered.
                // We can stop here.
                tracing::debug!("no new candidates or local targets; stopping");
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::analysis::AnalysisPass;
    use crate::attributes;
    use crate::storage::InMemoryStorage;
    use crate::types::attributes::*;

    #[test]
    fn test_control_flow_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut project = Project::from_file_with::<InMemoryStorage>(
                "tests/ls.elf",
                attributes![
                    ATTRIBUTE_PROJECT_PATH => "/tmp/ls.fudb",
                ],
            )?;
            let mut cfr = FunctionRecovery::new();

            cfr.add_candidate(0x4da0u64);
            cfr.add_candidate(0x6dd0u64);
            cfr.analyse(&mut project)?;

            Ok(())
        })
    }
}
