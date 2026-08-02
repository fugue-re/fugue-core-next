use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::analysis::function::recovery::FunctionStructuringContext;
use crate::analysis::non_returning::NonReturningTargets;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::ProjectView;
use crate::ir::{Address, CodeBlock, FunctionProperties, Insn};

pub(super) const NON_RETURNING_PROPAGATION_ANALYSER: &str = "non-returning-propagation";

enum BlockExit {
    Returns,
    Unknown,
    Via(Address),
}

impl BlockExit {
    fn from_terminator(terminator: &Insn) -> Self {
        if terminator.is_return() {
            return Self::Returns;
        }

        match terminator
            .flow_targets()
            .find_map(|target| target.kind().is_call().then_some(target.to()))
        {
            Some(target) => Self::Via(target),
            None => Self::Unknown,
        }
    }

    fn from_block(block: &CodeBlock) -> Self {
        if block.is_return() {
            return Self::Returns;
        }

        match block.direct_call_target() {
            Some(target) => Self::Via(target),
            None => Self::Unknown,
        }
    }
}

#[derive(Default)]
struct FunctionExits {
    returns: bool,
    targets: BTreeSet<Address>,
}

impl FunctionExits {
    fn add(&mut self, exit: BlockExit) {
        match exit {
            BlockExit::Returns | BlockExit::Unknown => self.returns = true,
            BlockExit::Via(target) => {
                self.targets.insert(target);
            }
        }
    }
}

#[derive(Default)]
struct ExitGraph {
    functions: BTreeMap<Address, FunctionExits>,
    callers: BTreeMap<Address, BTreeSet<Address>>,
    calls: BTreeSet<StaleCall>,
}

impl ExitGraph {
    fn from_project(project: &ProjectView<'_>, context: &FunctionStructuringContext) -> Self {
        let targets = NonReturningTargets::new(project);
        let mut graph = Self::default();

        for function in project.functions().iter() {
            let caller = function.entry();
            let mut exits = FunctionExits::default();

            for (_, id) in function.blocks() {
                let Some(block) = project.blocks().get_by_id(id) else {
                    continue;
                };

                graph.visit_committed_block(
                    &mut exits,
                    caller,
                    !function.has_successors(id),
                    &block,
                );
            }

            graph.functions.insert(caller, exits);
        }

        for (&caller, function) in context.pending_functions() {
            let mut exits = FunctionExits::default();

            for block in function.blocks() {
                graph.visit_pending_block(
                    &targets,
                    &mut exits,
                    caller,
                    block.successors().is_empty(),
                    block.insns().last().and_then(|&id| function.insn(id)),
                );
            }

            graph.functions.insert(caller, exits);
        }

        let known = graph.functions.keys().copied().collect::<BTreeSet<_>>();

        for exits in graph.functions.values_mut() {
            let mut escapes = false;

            exits.targets.retain(|target| {
                if targets.is_non_returning(*target) {
                    return false;
                }
                if known.contains(target) {
                    return true;
                }
                escapes = true;
                false
            });

            exits.returns |= escapes;
        }

        for (&entry, exits) in graph.functions.iter() {
            for &target in exits.targets.iter() {
                graph.callers.entry(target).or_default().insert(entry);
            }
        }

        graph
    }

    fn visit_committed_block(
        &mut self,
        exits: &mut FunctionExits,
        caller: Address,
        is_exit: bool,
        block: &CodeBlock,
    ) {
        if is_exit {
            exits.add(BlockExit::from_block(block));
            return;
        }

        if block.is_call()
            && !block.is_branch()
            && let Some(target) = block.direct_call_target()
        {
            self.calls.insert(StaleCall { caller, target });
        }
    }

    fn visit_pending_block(
        &mut self,
        targets: &NonReturningTargets<'_>,
        exits: &mut FunctionExits,
        caller: Address,
        is_exit: bool,
        terminator: Option<&Insn>,
    ) {
        if is_exit {
            match terminator {
                Some(terminator) => exits.add(BlockExit::from_terminator(terminator)),
                None => exits.returns = true,
            }
            return;
        }

        if let Some(target) = terminator.and_then(|insn| targets.suppressible_call(insn)) {
            self.calls.insert(StaleCall { caller, target });
        }
    }

    fn stale_calls<'a>(
        &'a self,
        targets: &'a NonReturningTargets<'a>,
        non_returning: &'a BTreeSet<Address>,
    ) -> impl Iterator<Item = &'a StaleCall> {
        self.calls.iter().filter(move |call| {
            non_returning.contains(&call.target) || targets.is_non_returning(call.target)
        })
    }

    fn non_returning(&self, project: &ProjectView<'_>) -> BTreeSet<Address> {
        let targets = NonReturningTargets::new(project);
        let mut returning = self
            .functions
            .iter()
            .filter(|(_, exits)| exits.returns)
            .map(|(&entry, _)| entry)
            .collect::<BTreeSet<_>>();

        let mut worklist = returning.iter().copied().collect::<VecDeque<_>>();

        while let Some(entry) = worklist.pop_front() {
            let Some(callers) = self.callers.get(&entry) else {
                continue;
            };

            for &caller in callers.iter() {
                if returning.insert(caller) {
                    worklist.push_back(caller);
                }
            }
        }

        self.functions
            .keys()
            .copied()
            .filter(|entry| !returning.contains(entry) && !targets.is_non_returning(*entry))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StaleCall {
    caller: Address,
    target: Address,
}

#[derive(Debug, Default)]
pub struct NonReturningPropagation;

impl NonReturningPropagation {
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisPass<FunctionStructuringContext> for NonReturningPropagation {
    fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        context: &mut FunctionStructuringContext,
    ) -> Result<(), AnalysisError> {
        let graph = ExitGraph::from_project(project, context);
        let non_returning = graph.non_returning(project);

        for &entry in non_returning.iter() {
            tracing::debug!("marking function at {entry} as non-returning");

            if let Some(function) = project.functions().get_by_address(entry) {
                let properties = function.properties() | FunctionProperties::NON_RETURNING;
                drop(function);

                context.set_function_properties(entry, properties);
                continue;
            }

            context
                .modify_pending_function(entry, |function| {
                    function.mark_non_returning();
                    Ok(())
                })
                .map_err(|e| AnalysisError::pass_failed(NON_RETURNING_PROPAGATION_ANALYSER, e))?;
        }

        let targets = NonReturningTargets::new(project);

        for &StaleCall { caller, target } in graph.stale_calls(&targets, &non_returning) {
            tracing::debug!("re-analysing {caller}: calls non-returning function at {target}");

            context.reanalyse_function(caller);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::analysis::function::recovery::{FunctionRecoveryConfig, FunctionRecoveryExtension};
    use crate::analysis::non_returning::NonReturningExterns;
    use crate::lifter::InsnResolver;
    use crate::loader::{Loadable, LoadableAnalysers, Loader};
    use crate::project::Project;
    use crate::registry;
    use crate::storage::{SegmentMappingCache, SegmentStorageError};

    struct Recovered {
        project: Project,
        insns: BTreeMap<Address, usize>,
        largest: usize,
    }

    fn recover(path: &str, enabled: bool) -> Result<Recovered, Box<dyn std::error::Error>> {
        let loader = Loader::from_file(path)?;
        let mut project = Project::new_transient(&loader)?;

        if enabled {
            NonReturningExterns::new(loader.platform().os()).analyse(&mut project)?;
        }

        let config = FunctionRecoveryConfig::default()
            .with_non_returning_analysis(enabled)
            .with_switch_analysis(true);
        let mut recovery = loader.analysers().function_recovery_with(config)?;

        for extension in registry::iter::<FunctionRecoveryExtension>() {
            extension.apply(&project, &mut recovery)?;
        }

        recovery.analyse(&mut project)?;

        let mut insns = BTreeMap::new();
        let mut largest = 0;
        let mut mappings = SegmentMappingCache::new();
        let mut resolver = InsnResolver::new(project.arch());

        for function in project.functions().iter() {
            largest = largest.max(function.blocks().len());

            for (_, id) in function.blocks() {
                let Some(block) = project.blocks().get_by_id(id) else {
                    continue;
                };

                let view = mappings.contiguous_view_from(project.segments(), block.address())?;
                let bytes = view
                    .as_contiguous()
                    .ok_or(SegmentStorageError::InvalidAddressRange)?;
                let resolved = resolver.resolve_extent(
                    block.address(),
                    block.size(),
                    block.context(),
                    bytes,
                )?;
                insns.extend(
                    resolved
                        .into_iter()
                        .map(|insn| (insn.address(), insn.size())),
                );
            }
        }

        Ok(Recovered {
            project,
            insns,
            largest,
        })
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_recovery_is_bounded_without_losing_code() -> Result<(), Box<dyn std::error::Error>> {
        for path in ["tests/ls.elf", "tests/hello-pe.exe"] {
            let baseline = recover(path, false)?;
            let bounded = recover(path, true)?;

            let arch = bounded.project.arch();
            let mut buffer = [0u8; 32];
            let lost = baseline
                .insns
                .iter()
                .filter(|(address, _)| !bounded.insns.contains_key(address))
                .filter(|(address, size)| {
                    let Ok(read) = bounded
                        .project
                        .segments()
                        .read_bytes(**address, &mut buffer)
                    else {
                        return true;
                    };
                    !buffer
                        .get(..read.min(**size))
                        .is_some_and(|bytes| arch.is_padding_pattern(bytes))
                })
                .map(|(address, _)| *address)
                .collect::<Vec<_>>();

            assert!(
                lost.is_empty(),
                "{} non-padding instructions are no longer recovered in {path}, starting at {:?}",
                lost.len(),
                lost.first()
            );

            assert!(
                bounded.largest <= baseline.largest,
                "largest function in {path} grew from {} to {} blocks",
                baseline.largest,
                bounded.largest
            );

            let propagated = bounded
                .project
                .functions()
                .iter()
                .filter(|function| function.is_non_returning() && !function.is_thunk())
                .count();

            assert!(
                propagated > 0,
                "propagation marked nothing beyond thunks in {path}"
            );
        }

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_reanalysis_preserves_recovered_switches() -> Result<(), Box<dyn std::error::Error>> {
        for path in ["tests/ls.elf", "tests/hello-pe.exe"] {
            let baseline = recover(path, false)?;
            let bounded = recover(path, true)?;

            let branches = baseline
                .project
                .switches()
                .iter()
                .map(|switch| switch.branch())
                .collect::<BTreeSet<_>>();
            let recovered = bounded
                .project
                .switches()
                .iter()
                .map(|switch| switch.branch())
                .collect::<BTreeSet<_>>();

            assert!(
                !branches.is_empty(),
                "no switches are recovered in {path}, so this proves nothing"
            );

            let lost = branches.difference(&recovered).collect::<Vec<_>>();

            assert!(
                lost.is_empty(),
                "{} switches are no longer recovered in {path}, starting at {:?}",
                lost.len(),
                lost.first()
            );
        }

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_indirect_call_targets_are_resolved() -> Result<(), Box<dyn std::error::Error>> {
        let Recovered { project, .. } = recover("tests/hello-pe.exe", false)?;
        let mut imports = 0;

        for function in project.functions().iter() {
            for (_, id) in function.blocks() {
                let Some(block) = project.blocks().get_by_id(id) else {
                    continue;
                };

                let Some(target) = block.direct_call_target() else {
                    continue;
                };

                if project
                    .symbols()
                    .get_by_address(target)
                    .any(|(_, entry)| entry.is_extern())
                {
                    imports += 1;
                }
            }
        }

        assert!(
            imports > 0,
            "no call resolved to an imported symbol, so the IAT pointer was never followed"
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_non_returning_calls_have_no_fall_through() -> Result<(), Box<dyn std::error::Error>> {
        for path in ["tests/ls.elf", "tests/hello-pe.exe"] {
            let Recovered { project, .. } = recover(path, true)?;
            let view = ProjectView::new(&project);
            let targets = NonReturningTargets::new(&view);

            let mut suppressed = 0;

            for function in project.functions().iter() {
                for (_, id) in function.blocks() {
                    let Some(block) = project.blocks().get_by_id(id) else {
                        continue;
                    };

                    let Some(target) = block.direct_call_target() else {
                        continue;
                    };

                    let is_non_returning =
                        block.is_call() && !block.is_branch() && targets.is_non_returning(target);

                    if !is_non_returning {
                        continue;
                    }

                    assert!(
                        !function.has_successors(id),
                        "call to a non-returning function at {} in {path} kept its fall-through",
                        block.last_address()
                    );

                    suppressed += 1;
                }
            }

            assert!(
                suppressed > 0,
                "no calls to non-returning functions in {path}"
            );
        }

        Ok(())
    }

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_recovery_reaches_a_fixpoint() -> Result<(), Box<dyn std::error::Error>> {
        for path in ["tests/ls.elf", "tests/hello-pe.exe"] {
            let first = recover(path, true)?;
            let second = recover(path, true)?;

            let layout = |recovered: &Recovered| {
                recovered
                    .project
                    .functions()
                    .iter()
                    .map(|function| (function.entry(), function.blocks().len()))
                    .collect::<BTreeSet<_>>()
            };

            assert_eq!(
                layout(&first),
                layout(&second),
                "recovery of {path} is not deterministic"
            );

            assert_eq!(
                first.insns, second.insns,
                "recovery of {path} covers different code on a second run"
            );
        }

        Ok(())
    }
}
