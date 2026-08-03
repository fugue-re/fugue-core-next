use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::{
    FunctionRecoveryExtension, FunctionRecoveryPatternMatcher,
};
use crate::analysis::function::{FunctionRecovery, FunctionRecoveryConfig};
use crate::arch::Arch;
use crate::extension::submit;
use crate::loader::elf::extensions::{AnalysisContext, FunctionRecoveryHandler};
use crate::loader::{Elf, Loadable, LoadableAnalysers};
use crate::platform::{CallingConvention, Format};
use crate::project::Project;

mod specs;

#[derive(Clone, Copy)]
pub struct ElfAnalysers<'a> {
    elf: &'a Elf<'a>,
}

impl<'a> ElfAnalysers<'a> {
    pub fn new(elf: &'a Elf<'a>) -> Self {
        Self { elf }
    }

    fn add_function_recovery_patterns(
        arch: &Arch,
        convention: CallingConvention,
        analyser: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        let mut pattern_matcher = FunctionRecoveryPatternMatcher::new();
        specs::FunctionRecoveryPatterns::apply(arch, convention, &mut pattern_matcher)?;
        analyser.add_candidate_discovery_pass("elf-loader-patterns", pattern_matcher);
        Ok(())
    }

    fn add_project_function_recovery_patterns(
        project: &Project,
        analyser: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        if project.platform().format() != Format::Elf {
            return Ok(());
        }

        let convention = project.platform().calling_convention();
        Self::add_function_recovery_patterns(project.arch(), convention, analyser)
    }
}

impl<'a> LoadableAnalysers for ElfAnalysers<'a> {
    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery, AnalysisError> {
        let mut analyser = FunctionRecovery::new_with(config);
        let arch = self.elf.architecture();
        let platform = self.elf.platform();
        let context = AnalysisContext::new(self.elf, arch, platform);

        context.apply_function_recovery_extensions(&mut analyser)?;

        Ok(analyser)
    }
}

submit! {
    FunctionRecoveryExtension::new(
        "elf-loader-patterns",
        ElfAnalysers::add_project_function_recovery_patterns,
    )
}

#[fugue_core::extension]
impl FunctionRecoveryHandler {
    const NAME: &str = "elf-loader-patterns";

    fn apply(
        context: &AnalysisContext<'_>,
        analyser: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        ElfAnalysers::add_function_recovery_patterns(
            context.arch(),
            context.calling_convention(),
            analyser,
        )
    }
}
