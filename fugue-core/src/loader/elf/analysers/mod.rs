use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::FunctionRecoveryPatternMatcher;
use crate::analysis::function::{FunctionRecovery, FunctionRecoveryConfig};
use crate::loader::elf::extensions::{AnalysisContext, FunctionRecoveryHandler};
use crate::loader::{Elf, Loadable, LoadableAnalysers};

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

impl<'a> LoadableAnalysers for ElfAnalysers<'a> {
    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery, AnalysisError> {
        let mut analyser = FunctionRecovery::new_with(config);
        let arch = self.elf.architecture();
        let context = AnalysisContext::new(self.elf, arch, self.elf.convention());

        context.configure_function_recovery(&mut analyser)?;

        Ok(analyser)
    }
}

#[fugue_core::extension]
impl FunctionRecoveryHandler {
    const NAME: &str = "elf-loader-patterns";

    fn configure_function_recovery(
        context: &AnalysisContext<'_>,
        analyser: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        let mut patttern_matcher = FunctionRecoveryPatternMatcher::new();

        let convention = context.convention().unwrap_or("default");

        specs::configure_analyser(context.arch(), convention, &mut patttern_matcher)?;

        analyser.add_candidate_discovery_pass("elf-loader-patterns", patttern_matcher);

        Ok(())
    }
}
