use crate::analysis::function::recovery::StructuredFunctionContext;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::AnalysisContext;

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

        let Some(target) = state.function().thunk_target() else {
            return Ok(());
        };

        if !project.is_non_returning_at(target) {
            return Ok(());
        }

        tracing::debug!(
            "marking thunk at {} to {target} as non-returning",
            state.function().entry()
        );

        state.function_mut().mark_non_returning();

        Ok(())
    }
}
