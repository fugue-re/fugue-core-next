use super::condition::AnalysisCondition;
use super::error::AnalysisError;
use super::group::AnalysisGroup;
use super::pass::AnalysisPass;
use crate::engine::ProjectView;

pub struct IteratedAnalysis<S = ()> {
    pass: Box<dyn AnalysisPass<S> + 'static>,
    condition: Box<dyn AnalysisCondition<S> + 'static>,
}

impl<S> IteratedAnalysis<S>
where
    S: 'static,
{
    pub fn new(
        pass: impl AnalysisPass<S> + 'static,
        condition: impl AnalysisCondition<S> + 'static,
    ) -> Self {
        Self {
            pass: Box::new(pass),
            condition: Box::new(condition),
        }
    }

    pub fn pass<T>(&self) -> Option<&T>
    where
        T: AnalysisPass<S>,
    {
        self.pass.downcast_ref::<T>()
    }

    pub fn pass_mut<T>(&mut self) -> Option<&mut T>
    where
        T: AnalysisPass<S>,
    {
        self.pass.downcast_mut::<T>()
    }

    pub fn condition(&self) -> &(dyn AnalysisCondition<S> + 'static) {
        &*self.condition
    }

    pub fn condition_mut(&mut self) -> &mut (dyn AnalysisCondition<S> + 'static) {
        &mut *self.condition
    }
}

impl<S> AnalysisPass<S> for IteratedAnalysis<S>
where
    S: 'static,
{
    fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        while self.condition.evaluate(state) {
            self.pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<S>> {
        self.pass.as_group()
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<S>> {
        self.pass.as_group_mut()
    }
}

pub struct ConditionalAnalysis<S = ()> {
    pass: Box<dyn AnalysisPass<S> + 'static>,
    condition: Box<dyn AnalysisCondition<S> + 'static>,
}

impl<S> ConditionalAnalysis<S>
where
    S: 'static,
{
    pub fn new(
        pass: impl AnalysisPass<S> + 'static,
        condition: impl AnalysisCondition<S> + 'static,
    ) -> Self {
        Self {
            pass: Box::new(pass),
            condition: Box::new(condition),
        }
    }

    pub fn pass<T>(&self) -> Option<&T>
    where
        T: AnalysisPass<S>,
    {
        self.pass.downcast_ref::<T>()
    }

    pub fn pass_mut<T>(&mut self) -> Option<&mut T>
    where
        T: AnalysisPass<S>,
    {
        self.pass.downcast_mut::<T>()
    }

    pub fn condition(&self) -> &(dyn AnalysisCondition<S> + 'static) {
        &*self.condition
    }

    pub fn condition_mut(&mut self) -> &mut (dyn AnalysisCondition<S> + 'static) {
        &mut *self.condition
    }
}

impl<S> AnalysisPass<S> for ConditionalAnalysis<S>
where
    S: 'static,
{
    fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        if self.condition.evaluate(state) {
            self.pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<S>> {
        self.pass.as_group()
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<S>> {
        self.pass.as_group_mut()
    }
}

pub struct StatefulAnalysis<S = ()> {
    pass: Box<dyn AnalysisPass<S> + 'static>,
    state: S,
}

impl<S> StatefulAnalysis<S>
where
    S: Send + 'static,
{
    pub fn new(pass: impl AnalysisPass<S> + 'static, state: S) -> Self {
        Self {
            pass: Box::new(pass),
            state,
        }
    }

    pub fn pass<T>(&self) -> Option<&T>
    where
        T: AnalysisPass<S>,
    {
        self.pass.downcast_ref::<T>()
    }

    pub fn pass_mut<T>(&mut self) -> Option<&mut T>
    where
        T: AnalysisPass<S>,
    {
        self.pass.downcast_mut::<T>()
    }

    pub fn state(&self) -> &S {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

// NOTE: AnalysisPass here will always be AnalysisPass<()>; this means that we cannot implement
// `as_group` or `as_group_mut` for `StatefulAnalysis` as it would require `S` to be `()` as well.
impl<S> AnalysisPass for StatefulAnalysis<S>
where
    S: Send + 'static,
{
    fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        _state: &mut (),
    ) -> Result<(), AnalysisError> {
        self.pass.analyse_with(project, &mut self.state)
    }
}

pub struct OneShotAnalysis<S = ()> {
    pass: Box<dyn AnalysisPass<S> + 'static>,
    executed: bool,
}

impl<S> OneShotAnalysis<S>
where
    S: 'static,
{
    pub fn new(pass: impl AnalysisPass<S> + 'static) -> Self {
        Self {
            pass: Box::new(pass),
            executed: false,
        }
    }

    pub fn pass<T>(&self) -> Option<&T>
    where
        T: AnalysisPass<S>,
    {
        self.pass.downcast_ref::<T>()
    }

    pub fn pass_mut<T>(&mut self) -> Option<&mut T>
    where
        T: AnalysisPass<S>,
    {
        self.pass.downcast_mut::<T>()
    }

    pub fn has_executed(&self) -> bool {
        self.executed
    }
}

impl<S> AnalysisPass<S> for OneShotAnalysis<S>
where
    S: 'static,
{
    fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        if !self.executed {
            self.executed = true;
            self.pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<S>> {
        self.pass.as_group()
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<S>> {
        self.pass.as_group_mut()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::{AnalysisPassExt, IterationLimit};

    fn no_op(_project: &ProjectView<'_>, _state: &mut ()) -> Result<(), AnalysisError> {
        Ok(())
    }

    #[test]
    fn iteration_limit_composes_with_an_analysis_pass() {
        let mut analysis = no_op.iterated(IterationLimit::new(3));
        let mut state = ();

        assert!(analysis.condition_mut().evaluate(&mut state));
        assert!(analysis.condition_mut().evaluate(&mut state));
        assert!(analysis.condition_mut().evaluate(&mut state));
        assert!(!analysis.condition_mut().evaluate(&mut state));
    }
}
