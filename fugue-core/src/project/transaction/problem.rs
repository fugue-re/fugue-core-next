use super::ProjectTransaction;
use crate::ir::{Address, Problem, ProblemId, ProblemKey, ProblemKind, ProblemScope};
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
        let key = ProblemKey::scoped(scope, kind);
        let observed_revision = self.project.revision();
        let (mut problem, repeated) = match self.staged_problems.get(&key) {
            Some(Some(problem)) => (problem.clone(), true),
            Some(None) | None => match self.project.problems.try_get_by_key(key)? {
                Some(problem) => (problem.as_ref().clone(), true),
                None => (
                    Problem::new_scoped(ProblemId::INVALID, scope, kind, observed_revision),
                    false,
                ),
            },
        };

        if repeated {
            problem.record_attempt(observed_revision);
        }
        self.staged_problems.insert(key, Some(problem));
        Ok(())
    }
}
