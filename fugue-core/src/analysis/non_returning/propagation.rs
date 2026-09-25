use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::analysis::function::recovery::InterFunctionStructuringContext;
use crate::analysis::non_returning::NonReturningTargets;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::{AnalysisContext, ProjectView};
use crate::ir::{Address, CodeBlock, FunctionProperties, Insn};

pub(crate) const NON_RETURNING_PROPAGATION_ANALYSER: &str = "non-returning-propagation";

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

        match block.call_target() {
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
    fn from_project(project: &ProjectView<'_>, context: &InterFunctionStructuringContext) -> Self {
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
                    &mut exits,
                    caller,
                    block.successors().is_empty(),
                    block.insn_ids().last().and_then(|&id| function.insn(id)),
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
            && let Some(target) = block.call_target()
        {
            self.calls.insert(StaleCall { caller, target });
        }
    }

    fn visit_pending_block(
        &mut self,
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

        if let Some(terminator) = terminator
            && terminator.is_call()
            && !terminator.is_branch()
            && let Some(target) = terminator.call_target()
        {
            self.calls.insert(StaleCall { caller, target });
        }
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

impl AnalysisPass<InterFunctionStructuringContext> for NonReturningPropagation {
    fn analyse_with(
        &mut self,
        analysis: &mut AnalysisContext<'_, '_>,
        state: &mut InterFunctionStructuringContext,
    ) -> Result<(), AnalysisError> {
        let project = &analysis.project;
        let graph = ExitGraph::from_project(project, state);
        let non_returning = graph.non_returning(project);

        for &entry in non_returning.iter() {
            tracing::debug!("marking function at {entry} as non-returning");

            if let Some(function) = project.functions().get_by_address(entry) {
                let properties = function.properties() | FunctionProperties::NON_RETURNING;
                drop(function);

                state.update_function_properties(entry, properties);
                continue;
            }

            state
                .modify_pending_function(entry, |function| {
                    function.mark_non_returning();
                    Ok(())
                })
                .map_err(|e| AnalysisError::pass_failed(NON_RETURNING_PROPAGATION_ANALYSER, e))?;
        }

        let targets = NonReturningTargets::new(project);

        for &StaleCall { caller, target } in graph.stale_calls(&targets, &non_returning) {
            tracing::debug!("re-analysing {caller}: calls non-returning function at {target}");

            state.reanalyse_function(caller);
        }

        Ok(())
    }
}
