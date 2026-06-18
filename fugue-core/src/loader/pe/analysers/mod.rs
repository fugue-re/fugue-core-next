use crate::analysis::AnalysisError;
use crate::analysis::core::{FunctionRecovery, FunctionRecoveryConfig};
use crate::loader::{LoadableAnalysers, Pe};

#[derive(Clone, Copy)]
pub struct PeAnalysers<'a> {
    pe: &'a Pe<'a>,
}

impl<'a> PeAnalysers<'a> {
    pub fn new(pe: &'a Pe<'a>) -> Self {
        Self { pe }
    }
}

impl<'a> LoadableAnalysers for PeAnalysers<'a> {
    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery, AnalysisError> {
        let _ = self.pe;
        Ok(FunctionRecovery::new_with(config))
    }
}
