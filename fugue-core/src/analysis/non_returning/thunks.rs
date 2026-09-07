use crate::analysis::function::recovery::StructuredFunctionContext;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::AnalysisContext;

const MAX_INSN_BYTES: usize = 32;
pub(crate) const NON_RETURNING_THUNK_ANALYSER: &str = "non-returning-thunk";

#[derive(Debug, Default)]
pub(crate) struct NonReturningThunk;

impl AnalysisPass<StructuredFunctionContext> for NonReturningThunk {
    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        state: &mut StructuredFunctionContext,
    ) -> Result<(), AnalysisError> {
        let project = &context.project;
        if state.function().is_non_returning() {
            return Ok(());
        }

        let [block] = state.function().blocks() else {
            return Ok(());
        };

        let Some(terminator) = block
            .insn_ids()
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
