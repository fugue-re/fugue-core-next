use super::ProjectTransaction;
use crate::ir::{Address, ProblemKind, ProblemScope};
use crate::project::ProjectError;

impl ProjectTransaction<'_> {
    pub fn add_problem(&mut self, address: Address, kind: ProblemKind) -> Result<(), ProjectError> {
        self.add_scoped_problem(ProblemScope::Address(address), kind)
    }

    pub(crate) fn add_scoped_problem(
        &mut self,
        scope: ProblemScope,
        kind: ProblemKind,
    ) -> Result<(), ProjectError> {
        self.problem_staging
            .insert(&self.project.problems, scope, kind, self.project.revision())
            .map_err(ProjectError::from)
    }
}
