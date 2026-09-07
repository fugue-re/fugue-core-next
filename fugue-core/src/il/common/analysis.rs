use super::IlArtefact;
use crate::analysis::AnalysisError;
use crate::engine::{AnalysisContext, DEFAULT_WORK_ITEM_MAX_ATTEMPTS, Priority};
use crate::ir::FunctionId;
use crate::project::{AnalysisPhase, ChangeKinds, Project};

pub trait IlAnalysis<I: IlArtefact>: Sized {
    fn analyse(ir: &I) -> Self;
}

pub trait IlAnalyser: Send + Sized + 'static {
    const NAME: &'static str;
    type Input: IlArtefact;

    fn build(project: &Project) -> Result<Self, AnalysisError>;

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
        context: &mut AnalysisContext<'_, '_>,
        function: FunctionId,
        input: &Self::Input,
    ) -> Result<(), AnalysisError>;

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::empty()
    }

    fn max_attempts(&self) -> usize {
        DEFAULT_WORK_ITEM_MAX_ATTEMPTS
    }
}
