use crate::analysis::AnalysisError;
use crate::analysis::core::{FunctionRecovery, FunctionRecoveryConfig};
use crate::loader::pe::extensions::AnalysisContext;
use crate::loader::{Loadable, LoadableAnalysers, Pe};

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
        let mut analyser = FunctionRecovery::new_with(config);
        let arch = self.pe.architecture();
        let platform = self.pe.platform();
        let context = AnalysisContext::new(self.pe, arch, platform);

        context.apply_function_recovery_extensions(&mut analyser)?;

        Ok(analyser)
    }
}
