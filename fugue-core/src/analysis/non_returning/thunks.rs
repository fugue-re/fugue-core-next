use crate::analysis::function::recovery::FunctionRecoveryState;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::ProjectView;

const MAX_INSN_BYTES: usize = 32;
pub(super) const NON_RETURNING_THUNK_ANALYSER: &str = "non-returning-thunk";

#[derive(Debug, Default)]
pub(super) struct NonReturningThunk;

impl AnalysisPass<FunctionRecoveryState> for NonReturningThunk {
    fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        state: &mut FunctionRecoveryState,
    ) -> Result<(), AnalysisError> {
        if state.function().is_non_returning() {
            return Ok(());
        }

        let [block] = state.function().blocks() else {
            return Ok(());
        };

        let Some(terminator) = block
            .insns()
            .last()
            .and_then(|&id| state.function().insn(id))
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

        let arch = project.arch();
        let (function, resolver) = state.function_and_resolver(arch);
        let entry = function.entry();
        let Ok(terminator) = resolver.resolve(address, bytes) else {
            return Ok(());
        };

        let Some(target) = terminator.resolve_indirect_target(|address, bytes| {
            project.segments().read_bytes_exact(address, bytes).is_ok()
        }) else {
            return Ok(());
        };

        if !project.is_non_returning_at(target) {
            return Ok(());
        }

        tracing::debug!("marking thunk at {} to {target} as non-returning", entry);

        let function = state.function_mut();
        function.mark_thunk();
        function.mark_non_returning();

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::analysis::function::recovery::{FunctionRecoveryConfig, FunctionRecoveryExtension};
    use crate::analysis::non_returning::NonReturningExterns;
    use crate::extension;
    use crate::loader::{Loadable, LoadableAnalysers, Loader};
    use crate::project::Project;

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_non_returning_thunks_are_marked() -> Result<(), Box<dyn std::error::Error>> {
        for path in ["tests/ls.elf", "tests/hello-pe.exe"] {
            let loader = Loader::from_file(path)?;
            let mut project = Project::new_transient(&loader)?;

            NonReturningExterns::new(loader.platform().os()).analyse(&mut project)?;

            let config = FunctionRecoveryConfig::default().with_non_returning_analysis(true);
            let mut recovery = loader.analysers().function_recovery_with(config)?;

            for extension in extension::iter::<FunctionRecoveryExtension>() {
                extension.apply(&project, &mut recovery)?;
            }

            recovery.analyse(&mut project)?;

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
