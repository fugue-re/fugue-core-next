use super::FunctionRecoveryError;
use crate::ir::IncompleteFunction;
use crate::project::Project;
use crate::types::Confidence;

pub struct FunctionRecoveryCommitContext {
    function: IncompleteFunction,
    confidence: Confidence,
}

impl FunctionRecoveryCommitContext {
    pub fn new(function: IncompleteFunction, confidence: Confidence) -> Self {
        Self {
            function,
            confidence,
        }
    }

    pub fn function(&self) -> &IncompleteFunction {
        &self.function
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub(crate) fn into_function(self) -> IncompleteFunction {
        self.function
    }
}

pub trait FunctionRecoveryCommitHook: Send {
    fn should_commit(
        &self,
        project: &Project,
        context: &FunctionRecoveryCommitContext,
    ) -> Result<bool, FunctionRecoveryError>;
}

impl<F> FunctionRecoveryCommitHook for F
where
    F: Fn(&Project, &FunctionRecoveryCommitContext) -> Result<bool, FunctionRecoveryError> + Send,
{
    fn should_commit(
        &self,
        project: &Project,
        context: &FunctionRecoveryCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        (self)(project, context)
    }
}

impl FunctionRecoveryCommitHook for Box<dyn FunctionRecoveryCommitHook + 'static> {
    fn should_commit(
        &self,
        project: &Project,
        context: &FunctionRecoveryCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        self.as_ref().should_commit(project, context)
    }
}

impl<T> FunctionRecoveryCommitHook for Option<T>
where
    T: FunctionRecoveryCommitHook,
{
    fn should_commit(
        &self,
        project: &Project,
        context: &FunctionRecoveryCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        match self {
            Some(hook) => hook.should_commit(project, context),
            None => Ok(true),
        }
    }
}
