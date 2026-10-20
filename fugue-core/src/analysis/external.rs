use crate::analysis::function::recovery::{
    FunctionRecovery, FunctionRecoveryExtension, StructuredFunctionContext,
};
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::{AnalysisContext, Priority};
use crate::project::Project;
use crate::storage::SegmentMappingProvenance;

pub(crate) const EXTERNAL_FUNCTIONS_ANALYSER: &str = "external-functions";

#[derive(Debug, Default)]
pub(crate) struct ExternalFunctions;

impl AnalysisPass<StructuredFunctionContext> for ExternalFunctions {
    fn priority(&self) -> Priority {
        Priority::ENRICHMENT
    }

    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        state: &mut StructuredFunctionContext,
    ) -> Result<(), AnalysisError> {
        if state.function().is_external() {
            return Ok(());
        }

        let entry = state.function().entry();
        if !state
            .context_mut()
            .mapping_cache_mut()
            .view_containing(context.project.segments(), entry)
            .is_some_and(|view| view.provenance() == SegmentMappingProvenance::External)
        {
            return Ok(());
        }

        tracing::debug!("marking function at {entry} as external");

        state.function_mut().mark_external();

        Ok(())
    }
}

#[fugue_core::extension]
impl FunctionRecoveryExtension {
    const NAME: &str = EXTERNAL_FUNCTIONS_ANALYSER;

    fn configure(_: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        recovery.add_post_structuring_pass(EXTERNAL_FUNCTIONS_ANALYSER, ExternalFunctions);
        Ok(())
    }
}
