use crate::analysis::function::recovery::FunctionRecoveryState;
use crate::analysis::non_returning::NonReturningTargets;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::project::Project;

const MAX_INSN_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, Default)]
pub struct NonReturningThunks;

impl NonReturningThunks {
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisPass<FunctionRecoveryState> for NonReturningThunks {
    fn analyse_with(
        &mut self,
        project: &mut Project,
        state: &mut FunctionRecoveryState,
    ) -> Result<(), AnalysisError> {
        if state.function.is_non_returning() {
            return Ok(());
        }

        let [block] = state.function.blocks() else {
            return Ok(());
        };

        let Some(terminator) = block
            .insns()
            .last()
            .and_then(|&id| state.function.insn(id))
            .filter(|insn| insn.is_flow())
        else {
            return Ok(());
        };

        let address = terminator.address();
        let mut bytes = [0u8; MAX_INSN_BYTES];

        let Ok(read) = project.segments().read_bytes(address, &mut bytes) else {
            return Ok(());
        };

        let Some(bytes) = bytes.get(..read) else {
            return Ok(());
        };

        let Ok(terminator) = state.resolver.resolve(address, bytes) else {
            return Ok(());
        };

        let targets = NonReturningTargets::new(project);

        let Some(target) = state
            .resolver
            .resolve_indirect_target(project.segments(), &terminator)
        else {
            return Ok(());
        };

        if !targets.is_non_returning(target) {
            return Ok(());
        }

        tracing::debug!(
            "marking thunk at {} to {target} as non-returning",
            state.function.entry()
        );

        state.function.mark_thunk();
        state.function.mark_non_returning();

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::AnalysisPass;
    use crate::analysis::function::recovery::{FunctionRecoveryConfig, FunctionRecoveryExtension};
    use crate::analysis::non_returning::NonReturningFromExterns;
    use crate::loader::{Loadable, LoadableAnalysers, Loader};
    use crate::registry;

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_non_returning_thunks_are_marked() -> Result<(), Box<dyn std::error::Error>> {
        for path in ["tests/ls.elf", "tests/hello-pe.exe"] {
            let loader = Loader::from_file(path)?;
            let mut project = Project::new_transient(&loader)?;

            NonReturningFromExterns::new(loader.platform().os()).analyse(&mut project)?;

            let config = FunctionRecoveryConfig::default().with_non_returning_analysis(true);
            let mut recovery = loader.analysers().function_recovery_with(config)?;

            for extension in registry::iter::<FunctionRecoveryExtension>() {
                extension.apply(&project, &mut recovery)?;
            }

            AnalysisPass::analyse(&mut recovery, &mut project)?;

            let thunks = project
                .functions()
                .iter()
                .filter(|function| function.is_thunk() && function.is_non_returning())
                .count();

            assert!(thunks > 0, "no non-returning thunks recovered in {path}");
        }

        Ok(())
    }
}
