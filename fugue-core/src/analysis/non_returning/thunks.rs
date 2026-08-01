use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::FunctionRecoveryState;
use crate::engine::ProjectView;
use crate::ir::Address;

const MAX_INSN_BYTES: usize = 32;

pub(in crate::analysis) fn analyse_non_returning_thunk(
    project: &ProjectView<'_>,
    state: &mut FunctionRecoveryState,
    non_returning_targets: &[Address],
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

    let Some(target) = resolver.resolve_indirect_target(project.segments(), &terminator) else {
        return Ok(());
    };

    if non_returning_targets.binary_search(&target).is_err() {
        return Ok(());
    }

    tracing::debug!("marking thunk at {} to {target} as non-returning", entry);

    let function = state.function_mut();
    function.mark_thunk();
    function.mark_non_returning();

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::analysis::function::recovery::{FunctionRecoveryConfig, FunctionRecoveryExtension};
    use crate::analysis::non_returning::NonReturningFromExterns;
    use crate::loader::{Loadable, LoadableAnalysers, Loader};
    use crate::project::Project;
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
