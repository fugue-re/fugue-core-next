use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::{FunctionRecovery, FunctionRecoveryExtension};
use crate::ir::{Address, Insn, InsnTarget};
use crate::project::Project;

pub mod externs;
pub use externs::NonReturningFromExterns;

pub mod propagation;
pub use propagation::NonReturningPropagation;

pub mod thunks;
pub use thunks::NonReturningThunks;

pub(crate) struct NonReturningTargets<'a> {
    project: &'a Project,
}

impl<'a> NonReturningTargets<'a> {
    pub(crate) fn new(project: &'a Project) -> Self {
        Self { project }
    }

    pub(crate) fn is_non_returning(&self, address: Address) -> bool {
        self.project
            .symbols()
            .get_by_address(address)
            .any(|(_, entry)| entry.is_non_returning())
            || self
                .project
                .functions()
                .get_by_address(address)
                .is_some_and(|function| function.is_non_returning())
    }

    pub(crate) fn called(&self, insn: &Insn) -> Option<Address> {
        insn.iter_targets().find_map(|(target, _, address)| {
            matches!(target, InsnTarget::InterSub(Some(_))).then_some(address)
        })
    }

    pub(crate) fn suppressible_call(&self, insn: &Insn) -> Option<Address> {
        self.is_suppressible(insn)
            .then(|| self.called(insn))
            .flatten()
    }

    pub(crate) fn calls_non_returning(&self, insn: &Insn) -> bool {
        self.suppressible_call(insn)
            .is_some_and(|target| self.is_non_returning(target))
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

        recovery
            .add_builder_post_structuring_pass("non-returning-thunks", NonReturningThunks::new());
        recovery.add_inter_function_structuring_pass(
            "non-returning-propagation",
            NonReturningPropagation::new(),
        );

        Ok(())
    }
}
