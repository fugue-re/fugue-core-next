use crate::analysis::function::recovery::StructuredFunctionContext;
use crate::analysis::{AnalysisError, AnalysisPass};
use crate::engine::AnalysisContext;
use crate::ir::FlowKind;

pub(crate) const SWITCH_OVERRIDES_ANALYSER: &str = "switch-overrides";

#[derive(Debug, Default)]
pub(crate) struct SwitchOverrides;

impl AnalysisPass<StructuredFunctionContext> for SwitchOverrides {
    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        state: &mut StructuredFunctionContext,
    ) -> Result<(), AnalysisError> {
        let project = &context.project;
        let overrides = state
            .function()
            .indirect_branches()
            .filter_map(|(_, site)| {
                let switch = project.switch_at(site)?;
                switch.is_override().then(|| switch.as_ref().clone())
            })
            .collect::<Vec<_>>();

        for switch in overrides {
            for case in switch.cases() {
                state.context_mut().add_local_target_with_context(
                    switch.branch(),
                    case.target().clone(),
                    FlowKind::SwitchBranch,
                );
            }
            state.function_mut().add_pending_switch(switch);
        }

        Ok(())
    }
}
