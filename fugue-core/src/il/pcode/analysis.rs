use crate::analysis::AnalysisError;
use crate::engine::change::ChangeKinds;
use crate::engine::{
    Analyser, AnalyserProvider, AnalysisContext, AnalysisPhase, IlAnalyserAdapter, ProjectUpdate,
    ProjectView,
};
use crate::extension;
use crate::il::common::IlAnalyser;
use crate::il::pcode::PCodeIr;
use crate::ir::{AddressRangeSet, FunctionId, ReferenceKind};
use crate::project::Project;

const PCODE_REFERENCE_ANALYSER: &str = "pcode-references";

struct PCodeReferenceAnalyser;

impl PCodeReferenceAnalyser {
    fn build(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
        Ok(Box::new(IlAnalyserAdapter::new(Self)))
    }
}

impl IlAnalyser for PCodeReferenceAnalyser {
    type Input = PCodeIr;

    fn name(&self) -> &'static str {
        PCODE_REFERENCE_ANALYSER
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::empty()
    }

    fn phase(&self) -> AnalysisPhase {
        AnalysisPhase::Derive
    }

    fn can_analyse(&self, _project: &Project) -> bool {
        true
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        function: FunctionId,
        pcode: &PCodeIr,
        _cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let mut coverage = AddressRangeSet::new();
        pcode.reference_coverage_into(&mut coverage);
        if let Some(function) = project.functions().get_by_id(function) {
            project
                .blocks()
                .coverage_into(function.blocks().map(|(_, block)| block), &mut coverage);
        }

        updates.push(ProjectUpdate::replace_derived_references(
            coverage,
            ReferenceKind::Data,
            pcode.data_references().collect(),
        ));
        Ok(())
    }

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::REFERENCES
    }
}

extension::submit! {
    AnalyserProvider::for_il::<PCodeIr>(PCODE_REFERENCE_ANALYSER, PCodeReferenceAnalyser::build)
}
