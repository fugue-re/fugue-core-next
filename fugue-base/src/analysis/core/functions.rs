use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use itertools::Itertools;
use thiserror::Error;

use crate::analysis::{AnalysisError, AnalysisPass};
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

pub struct FunctionRecovery {
    config: FunctionRecoveryConfig,
    candidates: VecDeque<(Address, ContextSet)>,
}

pub struct FunctionBuilder {
    entry: Address,
    candidates: VecDeque<(Address, ContextSet)>,
    contexts: BTreeMap<Address, ContextSet>,
    local_targets: BTreeSet<FlowTarget>,
    global_targets: BTreeSet<(Address, ContextSet)>,
}

#[derive(Debug, Error)]
pub enum FunctionBuilderError {
    #[error("failed to lift any instructions")]
    NoInstructions,
}

impl FunctionRecovery {
    pub fn new() -> Self {
        FunctionRecovery::new_with(FunctionRecoveryConfig::default())
    }

    pub fn new_with(config: FunctionRecoveryConfig) -> Self {
        FunctionRecovery {
            config,
            candidates: VecDeque::new(),
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

impl AnalysisPass<'_> for FunctionRecovery {
    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        let mut builder = FunctionBuilder::new();

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

            if let Err(e) = builder.analyse(project, address, context) {
                failures.insert(address);
                tracing::debug!("failed to analyse {address}: {e}");
                continue;
            }

            functions.insert(address);

            self.add_candidates_with_context(
                builder
                    .global_targets
                    .iter()
                    .filter(|(start, _)| !functions.contains(start) && !failures.contains(start))
                    .cloned(),
            );
        }

        Ok(())
    }
}

impl FunctionBuilder {
    pub fn new() -> Self {
        FunctionBuilder {
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
    ) -> Result<(), FunctionBuilderError> {
        let candidate = address.into();

        tracing::debug!("exploring from {candidate}");

        self.clear();
        self.entry = candidate;

        self.candidates.push_back((candidate, context));

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

            // In this stage we attempt to recover function control-flow and schedule more blocks
            // due to jump table resolution.
            break;
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
