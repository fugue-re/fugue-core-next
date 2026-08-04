use super::IlArtefact;
use crate::analysis::AnalysisError;
use crate::engine::change::ChangeKinds;
use crate::engine::{
    AnalysisContext, AnalysisPhase, DEFAULT_WORK_ITEM_MAX_ATTEMPTS, Priority, ProjectUpdate,
    ProjectView,
};
use crate::ir::FunctionId;
use crate::project::Project;

pub trait IlAnalysis<I: IlArtefact>: Sized {
    fn analyse(ir: &I) -> Self;
}

pub trait IlAnalyser: Send + 'static {
    type Input: IlArtefact;

    fn name(&self) -> &'static str;

    fn triggers(&self) -> ChangeKinds;

    fn phase(&self) -> AnalysisPhase {
        AnalysisPhase::default()
    }

    fn priority(&self) -> Priority {
        Priority::default()
    }

    fn can_analyse(&self, project: &Project) -> bool;

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        function: FunctionId,
        input: &Self::Input,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError>;

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::empty()
    }

    fn max_attempts(&self) -> usize {
        DEFAULT_WORK_ITEM_MAX_ATTEMPTS
    }
}
