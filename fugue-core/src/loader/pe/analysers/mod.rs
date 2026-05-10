use crate::analysis::AnalysisError;
use crate::analysis::core::{FunctionRecovery, FunctionRecoveryConfig};
use crate::loader::{LoadableAnalysers, Pe};
use crate::storage::ProjectStorageProvider;

#[derive(Clone, Copy)]
pub struct PeAnalysers<'a> {
    pe: &'a Pe<'a>,
}

impl<'a> PeAnalysers<'a> {
    pub fn new(pe: &'a Pe<'a>) -> Self {
        Self { pe }
    }
}

impl<'a, P> LoadableAnalysers<P> for PeAnalysers<'a>
where
    P: ProjectStorageProvider,
{
    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery<P>, AnalysisError> {
        let _ = self.pe;
        Ok(FunctionRecovery::new_with(config))
    }
}
