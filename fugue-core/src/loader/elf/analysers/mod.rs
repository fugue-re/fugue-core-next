use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::core::patterns::FunctionRecoveryPatternMatcher;
use crate::analysis::function::{FunctionRecovery, FunctionRecoveryConfig};
use crate::loader::{Elf, Loadable, LoadableAnalysers};
use crate::storage::ProjectStorageProvider;

mod specs;

#[derive(Clone, Copy)]
pub struct ElfAnalysers<'a> {
    elf: &'a Elf<'a>,
}

impl<'a> ElfAnalysers<'a> {
    pub fn new(elf: &'a Elf<'a>) -> Self {
        Self { elf }
    }
}

impl<'a, P> LoadableAnalysers<P> for ElfAnalysers<'a>
where
    P: ProjectStorageProvider,
{
    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery<P>, AnalysisError> {
        let mut analyser = FunctionRecovery::new_with(config);
        let mut patttern_matcher = FunctionRecoveryPatternMatcher::new();

        let arch = self.elf.architecture();
        let convention = self.elf.convention().unwrap_or("default");

        specs::configure_analyser(&arch, convention, &mut patttern_matcher)?;

        analyser.add_candidate_discovery_pass("elf-loader-patterns", patttern_matcher);

        Ok(analyser)
    }
}
