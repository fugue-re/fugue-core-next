use crate::project::Project;
use crate::storage::project::InMemoryProvider;
use crate::storage::ProjectStorageProvider;
use crate::types::Confidence;

use super::{FunctionRecoveryError, PartialFunction};

pub struct FunctionRecoveryCommitContext {
    function: PartialFunction,
    confidence: Confidence,
}

impl FunctionRecoveryCommitContext {
    pub fn new(function: PartialFunction, confidence: Confidence) -> Self {
        Self {
            function,
            confidence,
        }
    }

    pub fn function(&self) -> &PartialFunction {
        &self.function
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub(crate) fn into_function(self) -> PartialFunction {
        self.function
    }
}

pub trait FunctionRecoveryCommitHook<'a, P = InMemoryProvider>
where
    P: ProjectStorageProvider,
{
    fn should_commit(
        &self,
        project: &mut Project<P>,
        context: &FunctionRecoveryCommitContext,
    ) -> Result<bool, FunctionRecoveryError>;
}

impl<'a, P, F> FunctionRecoveryCommitHook<'a, P> for F
where
    F: Fn(&mut Project<P>, &FunctionRecoveryCommitContext) -> Result<bool, FunctionRecoveryError>,
    P: ProjectStorageProvider,
{
    fn should_commit(
        &self,
        project: &mut Project<P>,
        context: &FunctionRecoveryCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        (self)(project, context)
    }
}

impl<'a, P> FunctionRecoveryCommitHook<'a, P> for Box<dyn FunctionRecoveryCommitHook<'a, P> + 'a>
where
    P: ProjectStorageProvider,
{
    fn should_commit(
        &self,
        project: &mut Project<P>,
        context: &FunctionRecoveryCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        self.as_ref().should_commit(project, context)
    }
}

impl<'a, P, T> FunctionRecoveryCommitHook<'a, P> for Option<T>
where
    T: FunctionRecoveryCommitHook<'a, P>,
    P: ProjectStorageProvider,
{
    fn should_commit(
        &self,
        project: &mut Project<P>,
        context: &FunctionRecoveryCommitContext,
    ) -> Result<bool, FunctionRecoveryError> {
        match self {
            Some(hook) => hook.should_commit(project, context),
            None => Ok(true),
        }
    }
}
