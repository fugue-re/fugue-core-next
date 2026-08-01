use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::{FunctionRecovery, FunctionRecoveryExtension};
use crate::engine::ProjectView;
use crate::ir::{Address, Insn};
use crate::project::Project;

pub mod externs;
pub use externs::NonReturningFromExterns;

pub mod propagation;
pub use propagation::NonReturningPropagation;

pub(crate) mod thunks;
pub(in crate::analysis) use thunks::analyse_non_returning_thunk;

pub(crate) struct NonReturningTargets<'a> {
    project: &'a ProjectView<'a>,
}

impl<'a> NonReturningTargets<'a> {
    pub(crate) fn new(project: &'a ProjectView<'a>) -> Self {
        Self { project }
    }

    pub(crate) fn is_non_returning(&self, address: Address) -> bool {
        self.project.is_non_returning_at(address)
    }

    pub(crate) fn suppressible_call(&self, insn: &Insn) -> Option<Address> {
        if !self.is_suppressible(insn) {
            return None;
        }

        insn.direct_call_target()
    }

    fn is_suppressible(&self, insn: &Insn) -> bool {
        insn.is_call() && !insn.is_branch()
    }
}

#[fugue_core::extension]
impl FunctionRecoveryExtension {
    const NAME: &str = "non-returning";

    fn apply(_project: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        if !recovery.config().use_non_returning_analysis() {
            return Ok(());
        }

        recovery.add_inter_function_structuring_pass(
            "non-returning-propagation",
            NonReturningPropagation::new(),
        );

        Ok(())
    }
}
