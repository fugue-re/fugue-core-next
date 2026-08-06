use std::error::Error;

use thiserror::Error;

use super::control::Cancelled;

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error("analysis pass forms a cyclic dependency: {0} -> {1}")]
    CyclicDependency(String, String),
    #[error("analysis pass configuration `{name}` failed: {error}")]
    PassConfigurationFailed { name: String, error: anyhow::Error },
    #[error("analysis pass `{name}` failed: {error}")]
    PassFailed { name: String, error: anyhow::Error },
    #[error("analysis pass not found: {0}")]
    PassNotFound(String),
}

impl AnalysisError {
    pub fn pass_not_found(name: impl Into<String>) -> Self {
        Self::PassNotFound(name.into())
    }

    pub fn pass_failed<E>(name: impl Into<String>, error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::PassFailed {
            name: name.into(),
            error: error.into(),
        }
    }

    pub fn pass_configuration_failed<E>(name: impl Into<String>, error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::PassConfigurationFailed {
            name: name.into(),
            error: error.into(),
        }
    }
}
