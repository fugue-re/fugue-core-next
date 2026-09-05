use crate::analysis::function::recovery::FunctionRecoveryError;
use crate::engine::ProjectView;
use crate::ir::IncompleteFunction;
use crate::types::Confidence;

pub struct FunctionCommitContext {
    function: IncompleteFunction,
}

impl FunctionCommitContext {
    pub fn new(function: IncompleteFunction, confidence: Confidence) -> Self {
        Self {
            function: function.with_confidence(confidence),
        }
    }

    pub fn function(&self) -> &IncompleteFunction {
        &self.function
    }

    pub fn confidence(&self) -> Confidence {
        self.function.confidence()
    }

    pub(crate) fn into_function(self) -> IncompleteFunction {
        self.function
    }
}

pub trait FunctionCommitPolicy: Send {
    fn should_commit_immediately(
        &self,
        project: &ProjectView<'_>,
        context: &FunctionCommitContext,
    ) -> Result<bool, FunctionRecoveryError>;
}

impl<F> FunctionCommitPolicy for F
where
    F: Fn(&ProjectView<'_>, &FunctionCommitContext) -> Result<bool, FunctionRecoveryError> + Send,
{
    fn should_commit_immediately(
        &self,
        project: &ProjectView<'_>,
        context: &FunctionCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        (self)(project, context)
    }
}

impl FunctionCommitPolicy for Box<dyn FunctionCommitPolicy + 'static> {
    fn should_commit_immediately(
        &self,
        project: &ProjectView<'_>,
        context: &FunctionCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        self.as_ref().should_commit_immediately(project, context)
    }
}

impl<T> FunctionCommitPolicy for Option<T>
where
    T: FunctionCommitPolicy,
{
    fn should_commit_immediately(
        &self,
        project: &ProjectView<'_>,
        context: &FunctionCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        match self {
            Some(policy) => policy.should_commit_immediately(project, context),
            None => Ok(true),
        }
    }
}
