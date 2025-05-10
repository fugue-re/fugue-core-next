use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use itertools::Itertools;

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
        FunctionRecoveryConfig { max_blocks: 0x10000 }
    }
}

pub struct FunctionRecovery {
    config: FunctionRecoveryConfig,
    candidates: VecDeque<(Address, ContextSet)>,
}

pub struct FunctionBuilder {
    entry: Address,
    candidates: VecDeque<(Address, ContextSet)>,
    local_targets: BTreeSet<FlowTarget>,
    global_targets: BTreeSet<Address>,
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

        for symbol in project.iter_local_symbols() {
            tracing::debug!(
                "local function: {} (name: {:?})",
                symbol.address(),
                symbol.symbol()
            );
            self.add_candidate(symbol.address());
        }

        while let Some((address, context)) = self.candidates.pop_front() {
            if !project.storage.contains_segment(address) {
                tracing::trace!("skipping {address}: not mapped");
            }

            let _f = builder.analyse(project, address, context);

            self.add_candidates(builder.global_targets.iter().copied());
        }

        Ok(())
    }
}

impl FunctionBuilder {
    pub fn new() -> Self {
        FunctionBuilder {
            entry: Address::zero(),
            candidates: VecDeque::new(),
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
        self.local_targets.clear();
        self.global_targets.clear();
    }

    pub fn analyse(
        &mut self,
        project: &mut Project,
        address: impl Into<Address>,
        context: ContextSet,
    ) {
        let candidate = address.into();

        tracing::debug!("exploring from {candidate}");

        self.clear();
        self.entry = candidate;

        self.candidates.push_back((candidate, context));

        let mut insns = BTreeMap::<Address, _>::new();
        let mut bytes = [0u8; 32];

        'pass: loop {
            // This is the stage where we build blocks by collecting instructions and marking them.
            'outer: while let Some((block, context)) = self.candidates.pop_front() {
                if !project.storage.contains_segment(block) {
                    tracing::trace!("skipping {block}: not mapped");
                    continue 'outer;
                }

                // TODO: apply architecture-specific alignment check and context derivation
                // for the address.
                //
                // For example, on ARM/Thumb we need to check the LSB of the address and mask
                // it out, while returning a context that ensures the Thumb mode is set.

                if insns.contains_key(&block) {
                    continue;
                }

                let mut offset = 0usize;

                context.apply(block, project.lifter.context_mut());

                '_inner: loop {
                    let address = block + offset;

                    tracing::debug!("lifting at {address}");

                    // If we've already disassembled this instruction select the next candidate,
                    // otherwise get the entry ready for update.
                    let Entry::Vacant(entry) = insns.entry(address) else {
                        continue 'outer;
                    };

                    let Ok(size) = project.storage.read_bytes(address, &mut bytes) else {
                        tracing::trace!("skipping {block}: not mapped");
                        continue;
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
                                    if kind.is_local() {
                                        let Some(target) =
                                            FlowTarget::from_insn_target(insn, target, addr)
                                        else {
                                            continue;
                                        };

                                        if self.local_targets.insert(target) {
                                            // TODO: derive the context from the address via the architecture
                                            self.candidates.push_back((addr, ContextSet::new()));
                                        }
                                    } else {
                                        self.global_targets.insert(addr);
                                    }
                                }
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
                            // self.local_targets.remove(&address);
                            tracing::debug!("skipping {address}; lifting failed: {e}");
                            continue 'outer;
                        }
                    }
                }
            }

            tracing::debug!("{:?}", self.local_targets);

            // Structure the blocks
            let iinsns = &mut itertools::put_back(insns.iter());
            let mut iblocks = self
                .local_targets
                .iter()
                .map(|target| target.from())
                .skip(1)
                .chain(std::iter::once(Address::MAX));

            // Targets may contain invalid addresses...
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
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::analysis::AnalysisPass;
    use crate::attributes;
    use crate::storage::MemoryMappedStorage;
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
            let mut project = Project::from_file_with::<MemoryMappedStorage>(
                "tests/ls.elf",
                attributes![
                    ATTRIBUTE_PROJECT_PATH => "/tmp/ls.fudb",
                ],
            )?;
            let mut cfr = FunctionRecovery::new();

            cfr.analyse(&mut project)?;

            Ok(())
        })
    }
}
