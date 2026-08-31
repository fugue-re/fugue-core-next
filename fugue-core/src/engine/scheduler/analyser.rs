use std::any::Any;
use std::mem;
use std::sync::Arc;

use smallvec::SmallVec;

use super::super::{Analyser, AnalysisContext, Priority, ProjectUpdate, ProjectView};
use super::{AnalyserId, AnalyserOrder};
use crate::analysis::AnalysisError;
use crate::il::common::{IlAnalyser, IlArtefact, IlError, IlFormId};
use crate::il::registry::GeneratedArtefact;
use crate::ir::{AddressRange, AddressRangeSet, FunctionId};
use crate::project::{AnalysisPhase, ChangeKinds, Project};

pub(crate) struct IlAnalyserAdapter<A> {
    analyser: A,
}

impl<A> IlAnalyserAdapter<A> {
    pub(crate) fn new(analyser: A) -> Self {
        Self { analyser }
    }
}

pub(crate) struct IlAnalysisInput {
    artefact: Arc<dyn Any + Send + Sync>,
    form: IlFormId,
}

impl IlAnalysisInput {
    fn new(form: IlFormId, artefact: Arc<dyn Any + Send + Sync>) -> Self {
        Self { artefact, form }
    }

    pub(crate) fn artefact(&self) -> Arc<dyn Any + Send + Sync> {
        self.artefact.clone()
    }

    pub(crate) fn form(&self) -> &IlFormId {
        &self.form
    }

    pub(crate) fn into_artefact(self) -> Arc<dyn Any + Send + Sync> {
        self.artefact
    }
}

pub(crate) struct IlAnalysisInputs {
    artefacts: Vec<IlAnalysisInput>,
    function: FunctionId,
}

impl IlAnalysisInputs {
    pub(crate) fn new(function: FunctionId, artefacts: Vec<GeneratedArtefact>) -> Self {
        let artefacts = artefacts
            .into_iter()
            .map(|artefact| {
                let form = artefact.form().clone();
                IlAnalysisInput::new(form, Arc::from(artefact.into_value()))
            })
            .collect();
        Self {
            artefacts,
            function,
        }
    }

    pub(crate) fn contains(&self, form: &IlFormId) -> bool {
        self.artefacts
            .iter()
            .any(|artefact| artefact.form() == form)
    }

    pub(crate) fn function(&self) -> FunctionId {
        self.function
    }

    pub(crate) fn requested(&self, form: &IlFormId) -> Option<Arc<dyn Any + Send + Sync>> {
        self.artefacts
            .iter()
            .find(|artefact| artefact.form() == form)
            .map(IlAnalysisInput::artefact)
    }

    pub(crate) fn get<T: IlArtefact>(
        &self,
        function: FunctionId,
    ) -> Result<Option<Arc<T>>, IlError> {
        if function != self.function {
            return Ok(None);
        }
        let Some(artefact) = self
            .artefacts
            .iter()
            .find(|artefact| artefact.form() == &T::FORM)
        else {
            return Ok(None);
        };
        artefact
            .artefact()
            .downcast::<T>()
            .map(Some)
            .map_err(|_| IlError::mismatched_artefact(T::FORM))
    }

    pub(crate) fn into_artefacts(self) -> Vec<IlAnalysisInput> {
        self.artefacts
    }
}

impl<A> Analyser for IlAnalyserAdapter<A>
where
    A: IlAnalyser,
{
    fn name(&self) -> &'static str {
        A::NAME
    }

    fn triggers(&self) -> ChangeKinds {
        self.analyser.triggers()
    }

    fn phase(&self) -> AnalysisPhase {
        self.analyser.phase()
    }

    fn priority(&self) -> Priority {
        self.analyser.priority()
    }

    fn can_analyse(&self, project: &Project) -> bool {
        self.analyser.can_analyse(project)
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        regions: &AddressRangeSet,
        cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let mut functions = SmallVec::<[FunctionId; 4]>::new();
        if let Some(function) = project.il_analysis_function() {
            functions.push(function);
        } else {
            functions.extend(project.function_ids_overlapping(regions));
        }

        for function in functions {
            let Some(input) = project
                .lifted::<A::Input>(function)
                .map_err(|error| AnalysisError::pass_failed(A::NAME, error))?
            else {
                continue;
            };
            self.analyser
                .analyse(project, function, &input, cx, updates)?;
        }

        Ok(())
    }

    fn produces(&self) -> ChangeKinds {
        self.analyser.produces()
    }

    fn max_attempts(&self) -> usize {
        self.analyser.max_attempts()
    }
}

pub(crate) struct ScheduledAnalyser {
    analyser: Box<dyn Analyser>,
    claimed: AddressRangeSet,
    id: AnalyserId,
    il_input: Option<IlFormId>,
    max_attempts: usize,
    order: AnalyserOrder,
    phase: AnalysisPhase,
    priority: Priority,
    triggers: ChangeKinds,
}

impl ScheduledAnalyser {
    pub(crate) fn new(
        id: AnalyserId,
        analyser: Box<dyn Analyser>,
        il_input: Option<IlFormId>,
    ) -> Self {
        let max_attempts = analyser.max_attempts();
        let phase = analyser.phase();
        let priority = analyser.priority();
        let triggers = analyser.triggers();

        Self {
            analyser,
            claimed: AddressRangeSet::new(),
            id,
            il_input,
            max_attempts,
            order: AnalyserOrder::new(0),
            phase,
            priority,
            triggers,
        }
    }

    pub(crate) fn analyser(&self) -> &dyn Analyser {
        self.analyser.as_ref()
    }

    pub(crate) fn analyser_mut(&mut self) -> &mut dyn Analyser {
        self.analyser.as_mut()
    }

    pub(crate) fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    pub(crate) fn il_input(&self) -> Option<&IlFormId> {
        self.il_input.as_ref()
    }

    pub(crate) fn id(&self) -> AnalyserId {
        self.id
    }

    pub(crate) fn order(&self) -> AnalyserOrder {
        self.order
    }

    pub(crate) fn set_order(&mut self, order: AnalyserOrder) {
        self.order = order;
    }

    pub(crate) fn phase(&self) -> AnalysisPhase {
        self.phase
    }

    pub(crate) fn priority(&self) -> Priority {
        self.priority
    }

    pub(crate) fn triggers(&self) -> ChangeKinds {
        self.triggers
    }

    pub(crate) fn claim(&mut self, range: AddressRange) {
        self.claimed.insert_range(range);
    }

    pub(crate) fn clear_claimed(&mut self) {
        self.claimed = AddressRangeSet::new();
    }

    pub(crate) fn retract_claimed(&mut self, range: AddressRange) {
        self.claimed.remove_range(range);
    }

    pub(crate) fn take_claimed(&mut self) -> AddressRangeSet {
        mem::take(&mut self.claimed)
    }
}
