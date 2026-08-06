use std::borrow::Borrow;
use std::marker::PhantomData;

use indexmap::IndexMap;

use super::error::AnalysisError;
use super::pass::AnalysisPass;
use crate::engine::ProjectView;

pub struct AnalysisGroup<S = ()> {
    passes: IndexMap<String, Box<dyn AnalysisPass<S> + 'static>>,
    state: PhantomData<fn(S)>,
}

impl<S> Default for AnalysisGroup<S>
where
    S: 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> AnalysisGroup<S>
where
    S: 'static,
{
    pub fn new() -> Self {
        Self {
            passes: IndexMap::new(),
            state: PhantomData,
        }
    }

    pub fn get_pass<T>(&self, name: impl Borrow<str>) -> Option<&T>
    where
        T: AnalysisPass<S>,
    {
        self.passes
            .get(name.borrow())
            .and_then(|pass| pass.downcast_ref::<T>())
    }

    pub fn get_pass_mut<T>(&mut self, name: impl Borrow<str>) -> Option<&mut T>
    where
        T: AnalysisPass<S>,
    {
        self.passes
            .get_mut(name.borrow())
            .and_then(|pass| pass.downcast_mut::<T>())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &(dyn AnalysisPass<S> + 'static))> {
        self.passes
            .iter()
            .map(|(name, pass)| (name.as_ref(), pass.as_ref()))
    }

    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&str, &mut (dyn AnalysisPass<S> + 'static))> {
        self.passes
            .iter_mut()
            .map(move |(name, pass)| (name.as_ref(), pass.as_mut()))
    }

    pub fn len(&self) -> usize {
        self.passes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }

    pub fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        for pass in self.passes.values_mut() {
            pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    pub fn add_pass(&mut self, name: impl Into<String>, pass: impl AnalysisPass<S> + 'static) {
        self.passes.insert(name.into(), Box::new(pass));
    }

    pub fn insert_after(
        &mut self,
        target: impl Borrow<str>,
        name: impl Into<String>,
        pass: impl AnalysisPass<S> + 'static,
    ) {
        let target = target.borrow();

        if let Some(index) = self.passes.get_index_of(target) {
            self.passes
                .insert_before(index + 1, name.into(), Box::new(pass));
        } else {
            self.passes.insert(name.into(), Box::new(pass));
        }
    }

    pub fn insert_before(
        &mut self,
        target: impl Borrow<str>,
        name: impl Into<String>,
        pass: impl AnalysisPass<S> + 'static,
    ) {
        let target = target.borrow();

        if let Some(index) = self.passes.get_index_of(target) {
            self.passes
                .insert_before(index, name.into(), Box::new(pass));
        } else {
            self.passes.insert(name.into(), Box::new(pass));
        }
    }
}

impl<S> AnalysisPass<S> for AnalysisGroup<S>
where
    S: 'static,
{
    fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        AnalysisGroup::analyse_with(self, project, state)
    }

    fn as_group(&self) -> Option<&AnalysisGroup<S>> {
        Some(self)
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<S>> {
        Some(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn no_op(_project: &ProjectView<'_>, _state: &mut ()) -> Result<(), AnalysisError> {
        Ok(())
    }

    #[test]
    fn insert_after_places_pass_after_target() {
        let mut group = AnalysisGroup::new();
        group.add_pass("first", no_op);
        group.add_pass("last", no_op);
        group.insert_after("first", "middle", no_op);

        assert_eq!(
            group.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            ["first", "middle", "last"]
        );
    }

    #[test]
    fn insert_after_the_last_pass_moves_an_existing_pass_to_the_end() {
        let mut group = AnalysisGroup::new();
        group.add_pass("first", no_op);
        group.add_pass("second", no_op);
        group.add_pass("third", no_op);
        group.insert_after("third", "first", no_op);

        assert_eq!(
            group.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            ["second", "third", "first"]
        );
    }
}
