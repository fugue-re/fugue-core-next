use downcast_rs::{Downcast, impl_downcast};

use super::combinator::{ConditionalAnalysis, IteratedAnalysis, OneShotAnalysis, StatefulAnalysis};
use super::condition::AnalysisCondition;
use super::error::AnalysisError;
use super::group::AnalysisGroup;
use crate::engine::AnalysisContext;

pub trait AnalysisPass<S = ()>: Downcast + Send {
    fn can_analyse(&self, _context: &AnalysisContext<'_, '_>) -> bool {
        true
    }

    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        state: &mut S,
    ) -> Result<(), AnalysisError>;

    fn as_group(&self) -> Option<&AnalysisGroup<S>> {
        None
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<S>> {
        None
    }
}

impl_downcast!(AnalysisPass<S>);

impl<S, F> AnalysisPass<S> for F
where
    F: for<'a, 'p> FnMut(&mut AnalysisContext<'a, 'p>, &mut S) -> Result<(), AnalysisError>
        + Send
        + 'static,
    S: 'static,
{
    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        self(context, state)
    }
}

pub trait AnalysisPassExt<S>
where
    S: 'static,
{
    fn conditional(self, condition: impl AnalysisCondition<S> + 'static) -> ConditionalAnalysis<S>
    where
        Self: AnalysisPass<S> + Sized + 'static,
    {
        ConditionalAnalysis::new(self, condition)
    }

    fn iterated(self, condition: impl AnalysisCondition<S> + 'static) -> IteratedAnalysis<S>
    where
        Self: AnalysisPass<S> + Sized + 'static,
    {
        IteratedAnalysis::new(self, condition)
    }

    fn with_state(self, state: S) -> StatefulAnalysis<S>
    where
        Self: AnalysisPass<S> + Sized + 'static,
        S: Send,
    {
        StatefulAnalysis::new(self, state)
    }

    fn one_shot(self) -> OneShotAnalysis<S>
    where
        Self: AnalysisPass<S> + Sized + 'static,
    {
        OneShotAnalysis::new(self)
    }
}

impl<S, T> AnalysisPassExt<S> for T
where
    T: AnalysisPass<S> + Sized + 'static,
    S: 'static,
{
}
