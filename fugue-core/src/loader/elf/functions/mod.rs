use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::{
    FunctionRecovery, FunctionRecoveryExtension, FunctionRecoveryPatternMatcher,
};
use crate::platform::Format;
use crate::project::Project;

mod specs;

#[fugue_core::extension]
impl FunctionRecoveryExtension {
    const NAME: &str = "elf-function-recovery";

    fn configure(project: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        if project.platform().format() != Format::Elf {
            return Ok(());
        }

        let mut patterns = FunctionRecoveryPatternMatcher::new();
        specs::apply(
            project.arch(),
            project.platform().calling_convention(),
            &mut patterns,
        )?;
        recovery.add_candidate_discovery_pass("elf-function-recovery-patterns", patterns);

        Ok(())
    }
}
