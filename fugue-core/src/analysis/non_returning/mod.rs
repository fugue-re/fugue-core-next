use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::{FunctionRecovery, FunctionRecoveryExtension};
use crate::engine::ProjectView;
use crate::ir::Address;
use crate::project::Project;

pub mod externs;
pub use externs::NonReturningExterns;

pub mod propagation;
use propagation::NON_RETURNING_PROPAGATION_ANALYSER;
pub use propagation::NonReturningPropagation;

mod thunks;
use thunks::{NON_RETURNING_THUNK_ANALYSER, NonReturningThunk};

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
}

#[fugue_core::extension]
impl FunctionRecoveryExtension {
    const NAME: &str = "non-returning";

    fn configure(_: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        if !recovery.config().non_returning_analysis() {
            return Ok(());
        }

        recovery.add_inter_function_structuring_pass(
            NON_RETURNING_PROPAGATION_ANALYSER,
            NonReturningPropagation::new(),
        );
        recovery.add_post_structuring_pass(NON_RETURNING_THUNK_ANALYSER, NonReturningThunk);

        Ok(())
    }
}
