use std::borrow::Borrow;

use downcast_rs::{Downcast, impl_downcast};
use indexmap::IndexMap;
use thiserror::Error;
use uuid::Uuid;

use crate::project::Project;
use crate::storage::ProjectStorageProvider;
use crate::storage::project::InMemoryProvider;

pub mod function;

pub mod core {
    pub use super::function::recovery::{
        FunctionRecovery, FunctionRecoveryConfig, FunctionRecoveryError,
    };
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("analysis pass forms a cyclic dependency: {0} -> {1}")]
    CyclicDependency(String, String),
    #[error("analysis pass not found: {0}")]
    PassNotFound(String),
    #[error("analysis pass configuration failed: {0}")]
    PassConfigurationFailed(String, anyhow::Error),
    #[error("analysis pass failed: {0}")]
    PassFailed(String, anyhow::Error),
}

impl AnalysisError {
    pub fn pass_not_found(name: impl Into<String>) -> Self {
        AnalysisError::PassNotFound(name.into())
    }

    pub fn pass_failed<E>(name: impl Into<String>, error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static, {
        AnalysisError::PassFailed(name.into(), error.into())
    }

    pub fn pass_configuration_failed<E>(name: impl Into<String>, error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static, {
        AnalysisError::PassConfigurationFailed(name.into(), error.into())
    }
}

pub type NoState = ();
pub type BoxedAnalysisPass<P = InMemoryProvider, S = NoState> =
    Box<dyn AnalysisPass<P, S> + 'static>;

pub struct AnalysisManager<P = InMemoryProvider, S = NoState>
where
    P: ProjectStorageProvider, {
    passes: IndexMap<String, Box<dyn AnalysisPass<P, S> + 'static>>,
}

impl<P, S> Default for AnalysisManager<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<P, S> AnalysisManager<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    pub fn new() -> Self {
        AnalysisManager {
            passes: IndexMap::new(),
        }
    }

    pub fn add_pass(&mut self, name: impl Into<String>, pass: impl AnalysisPass<P, S> + 'static) {
        self.passes.insert(name.into(), Box::new(pass));
    }

    pub fn get_pass<T>(&self, name: impl Borrow<str>) -> Option<&T>
    where
        T: AnalysisPass<P, S>, {
        self.get_boxed_pass(name)
            .and_then(|pass| pass.as_ref().downcast_ref::<T>())
    }

    pub fn get_boxed_pass(&self, name: impl Borrow<str>) -> Option<&BoxedAnalysisPass<P, S>> {
        self.passes.get(name.borrow())
    }

    pub fn get_pass_mut<T>(&mut self, name: impl Borrow<str>) -> Option<&mut T>
    where
        T: AnalysisPass<P, S>, {
        self.get_boxed_pass_mut(name)
            .and_then(|pass| pass.as_mut().downcast_mut::<T>())
    }

    pub fn get_boxed_pass_mut(
        &mut self,
        name: impl Borrow<str>,
    ) -> Option<&mut BoxedAnalysisPass<P, S>> {
        self.passes.get_mut(name.borrow())
    }

    pub fn insert_after(
        &mut self,
        target: impl Borrow<str>,
        name: impl Into<String>,
        pass: impl AnalysisPass<P, S> + 'static,
    ) {
        let target = target.borrow();

        if let Some(index) = self.passes.get_index_of(target) {
            self.passes.shift_insert(index, name.into(), Box::new(pass));
        } else {
            self.passes.insert(name.into(), Box::new(pass));
        }
    }

    pub fn insert_before(
        &mut self,
        target: impl Borrow<str>,
        name: impl Into<String>,
        pass: impl AnalysisPass<P, S> + 'static,
    ) {
        let target = target.borrow();

        if let Some(index) = self.passes.get_index_of(target) {
            self.passes
                .insert_before(index, name.into(), Box::new(pass));
        } else {
            self.passes.insert(name.into(), Box::new(pass));
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &BoxedAnalysisPass<P, S>)> {
        self.passes.iter().map(|(name, pass)| (name.as_ref(), pass))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&str, &mut BoxedAnalysisPass<P, S>)> {
        self.passes
            .iter_mut()
            .map(move |(name, pass)| (name.as_ref(), pass))
    }

    pub fn passes(&self) -> impl Iterator<Item = (&str, &BoxedAnalysisPass<P, S>)> {
        self.iter()
    }

    pub fn passes_mut(&mut self) -> impl Iterator<Item = (&str, &mut BoxedAnalysisPass<P, S>)> {
        self.iter_mut()
    }

    pub fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        pass_name: impl Borrow<str>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        let pass_name = pass_name.borrow();
        if let Some(pass) = self.passes.get_mut(pass_name) {
            pass.analyse_with(project, state)
        } else {
            Err(AnalysisError::PassNotFound(pass_name.to_owned()))
        }
    }
}

impl AnalysisManager {
    pub fn analyse(&mut self, project: &mut Project, pass_name: &str) -> Result<(), AnalysisError> {
        self.analyse_with(project, pass_name, &mut Default::default())
    }
}

pub trait AnalysisPass<P = InMemoryProvider, S = NoState>: Downcast
where
    P: ProjectStorageProvider, {
    fn analyse(&mut self, #[allow(unused)] project: &mut Project<P>) -> Result<(), AnalysisError> {
        unimplemented!(
            "either `AnalysisPass::analyse` or `AnalysisPass::analyse_with` must be implemented"
        )
    }

    fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        #[allow(unused)] state: &mut S,
    ) -> Result<(), AnalysisError> {
        self.analyse(project)
    }

    fn as_group(&self) -> Option<&AnalysisGroup<P, S>> {
        None
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<P, S>> {
        None
    }
}

impl_downcast!(AnalysisPass<P, S> where P: ProjectStorageProvider);

impl<P, S, F> AnalysisPass<P, S> for F
where
    F: FnMut(&mut Project<P>, &mut S) -> Result<(), AnalysisError> + 'static,
    P: ProjectStorageProvider,
    S: 'static,
{
    fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        self(project, state)
    }
}

pub trait AnalysisCondition<P, S>
where
    P: ProjectStorageProvider, {
    fn evaluate(&mut self, state: &mut S) -> bool;
}

impl<F, P, S> AnalysisCondition<P, S> for F
where
    F: FnMut(&mut S) -> bool,
    P: ProjectStorageProvider,
{
    fn evaluate(&mut self, state: &mut S) -> bool {
        self(state)
    }
}

impl<P, S> AnalysisCondition<P, S> for usize
where
    P: ProjectStorageProvider,
{
    fn evaluate(&mut self, _state: &mut S) -> bool {
        if let Some(nself) = self.checked_sub(1) {
            *self = nself;
            true
        } else {
            false
        }
    }
}

pub struct AnalysisGroup<P = InMemoryProvider, S = NoState>
where
    P: ProjectStorageProvider, {
    passes: IndexMap<String, Box<dyn AnalysisPass<P, S> + 'static>>,
}

impl<P, S, T> FromIterator<T> for AnalysisGroup<P, S>
where
    T: AnalysisPass<P, S> + 'static,
    P: ProjectStorageProvider,
    S: 'static,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut group = AnalysisGroup::new();
        group.add_passes("pass", iter);
        group
    }
}

impl<P, S> Default for AnalysisGroup<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<P, S> AnalysisGroup<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    pub fn new() -> Self {
        AnalysisGroup {
            passes: IndexMap::new(),
        }
    }

    pub fn add_pass(&mut self, name: impl Into<String>, pass: impl AnalysisPass<P, S> + 'static) {
        self.passes.insert(name.into(), Box::new(pass));
    }

    pub fn add_passes(
        &mut self,
        prefix: impl Into<String>,
        passes: impl IntoIterator<Item = impl AnalysisPass<P, S> + 'static>,
    ) {
        let prefix = prefix.into();
        self.passes.extend(passes.into_iter().map(|pass| {
            let name = format!("{prefix}-{}", Uuid::now_v7().as_hyphenated());
            (name, Box::new(pass) as Box<dyn AnalysisPass<P, S>>)
        }));
    }

    pub fn get_boxed_pass(&self, name: impl Borrow<str>) -> Option<&BoxedAnalysisPass<P, S>> {
        self.passes.get(name.borrow())
    }

    pub fn get_pass<T>(&self, name: impl Borrow<str>) -> Option<&T>
    where
        T: AnalysisPass<P, S>, {
        self.get_boxed_pass(name)
            .and_then(|pass| pass.as_ref().downcast_ref::<T>())
    }

    pub fn get_boxed_pass_mut(
        &mut self,
        name: impl Borrow<str>,
    ) -> Option<&mut BoxedAnalysisPass<P, S>> {
        self.passes.get_mut(name.borrow())
    }

    pub fn get_pass_mut<T>(&mut self, name: impl Borrow<str>) -> Option<&mut T>
    where
        T: AnalysisPass<P, S>, {
        self.get_boxed_pass_mut(name)
            .and_then(|pass| pass.as_mut().downcast_mut::<T>())
    }

    pub fn insert_after(
        &mut self,
        target: impl Borrow<str>,
        name: impl Into<String>,
        pass: impl AnalysisPass<P, S> + 'static,
    ) {
        let target = target.borrow();

        if let Some(index) = self.passes.get_index_of(target) {
            self.passes.shift_insert(index, name.into(), Box::new(pass));
        } else {
            self.passes.insert(name.into(), Box::new(pass));
        }
    }

    pub fn insert_before(
        &mut self,
        target: impl Borrow<str>,
        name: impl Into<String>,
        pass: impl AnalysisPass<P, S> + 'static,
    ) {
        let target = target.borrow();

        if let Some(index) = self.passes.get_index_of(target) {
            self.passes
                .insert_before(index, name.into(), Box::new(pass));
        } else {
            self.passes.insert(name.into(), Box::new(pass));
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &BoxedAnalysisPass<P, S>)> {
        self.passes.iter().map(|(name, pass)| (name.as_ref(), pass))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&str, &mut BoxedAnalysisPass<P, S>)> {
        self.passes
            .iter_mut()
            .map(move |(name, pass)| (name.as_ref(), pass))
    }

    pub fn passes(&self) -> impl Iterator<Item = (&str, &BoxedAnalysisPass<P, S>)> {
        self.iter()
    }

    pub fn passes_mut(&mut self) -> impl Iterator<Item = (&str, &mut BoxedAnalysisPass<P, S>)> {
        self.iter_mut()
    }

    pub fn len(&self) -> usize {
        self.passes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }
}

impl<P, S> AnalysisPass<P, S> for AnalysisGroup<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        for pass in self.passes.values_mut() {
            pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<P, S>> {
        Some(self)
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<P, S>> {
        Some(self)
    }
}

pub struct IteratedAnalysis<P = InMemoryProvider, S = NoState>
where
    P: ProjectStorageProvider, {
    pass: Box<dyn AnalysisPass<P, S> + 'static>,
    condition: Box<dyn AnalysisCondition<P, S> + 'static>,
}

impl<P, S> IteratedAnalysis<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    pub fn new(
        pass: impl AnalysisPass<P, S> + 'static,
        condition: impl AnalysisCondition<P, S> + 'static,
    ) -> Self {
        IteratedAnalysis {
            pass: Box::new(pass),
            condition: Box::new(condition),
        }
    }

    pub fn boxed_pass(&self) -> &BoxedAnalysisPass<P, S> {
        &self.pass
    }

    pub fn boxed_pass_mut(&mut self) -> &mut BoxedAnalysisPass<P, S> {
        &mut self.pass
    }

    pub fn pass<T>(&self) -> Option<&T>
    where
        T: AnalysisPass<P, S>, {
        self.pass.as_ref().downcast_ref::<T>()
    }

    pub fn pass_mut<T>(&mut self) -> Option<&mut T>
    where
        T: AnalysisPass<P, S>, {
        self.pass.as_mut().downcast_mut::<T>()
    }

    pub fn condition(&self) -> &(dyn AnalysisCondition<P, S> + 'static) {
        &*self.condition
    }

    pub fn condition_mut(&mut self) -> &mut Box<dyn AnalysisCondition<P, S> + 'static> {
        &mut self.condition
    }
}

impl<P, S> AnalysisPass<P, S> for IteratedAnalysis<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        while self.condition.evaluate(state) {
            self.pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<P, S>> {
        self.pass.as_group()
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<P, S>> {
        self.pass.as_group_mut()
    }
}

pub struct ConditionalAnalysis<P = InMemoryProvider, S = NoState>
where
    P: ProjectStorageProvider, {
    pass: Box<dyn AnalysisPass<P, S> + 'static>,
    condition: Box<dyn AnalysisCondition<P, S> + 'static>,
}

impl<P, S> ConditionalAnalysis<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    pub fn new(
        pass: impl AnalysisPass<P, S> + 'static,
        condition: impl AnalysisCondition<P, S> + 'static,
    ) -> Self {
        ConditionalAnalysis {
            pass: Box::new(pass),
            condition: Box::new(condition),
        }
    }

    pub fn boxed_pass(&self) -> &BoxedAnalysisPass<P, S> {
        &self.pass
    }

    pub fn boxed_pass_mut(&mut self) -> &mut BoxedAnalysisPass<P, S> {
        &mut self.pass
    }

    pub fn pass<T>(&self) -> Option<&T>
    where
        T: AnalysisPass<P, S>, {
        self.pass.as_ref().downcast_ref::<T>()
    }

    pub fn pass_mut<T>(&mut self) -> Option<&mut T>
    where
        T: AnalysisPass<P, S>, {
        self.pass.as_mut().downcast_mut::<T>()
    }

    pub fn condition(&self) -> &(dyn AnalysisCondition<P, S> + 'static) {
        &*self.condition
    }

    pub fn condition_mut(&mut self) -> &mut Box<dyn AnalysisCondition<P, S> + 'static> {
        &mut self.condition
    }
}

impl<P, S> AnalysisPass<P, S> for ConditionalAnalysis<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        if self.condition.evaluate(state) {
            self.pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<P, S>> {
        self.pass.as_group()
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<P, S>> {
        self.pass.as_group_mut()
    }
}

pub struct StatefulAnalysis<P = InMemoryProvider, S = NoState>
where
    P: ProjectStorageProvider, {
    pass: Box<dyn AnalysisPass<P, S> + 'static>,
    state: S,
}

impl<P, S> StatefulAnalysis<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    pub fn new(pass: impl AnalysisPass<P, S> + 'static, state: S) -> Self {
        StatefulAnalysis {
            pass: Box::new(pass),
            state,
        }
    }

    pub fn boxed_pass(&self) -> &BoxedAnalysisPass<P, S> {
        &self.pass
    }

    pub fn boxed_pass_mut(&mut self) -> &mut BoxedAnalysisPass<P, S> {
        &mut self.pass
    }

    pub fn pass<T>(&self) -> Option<&T>
    where
        T: AnalysisPass<P, S>, {
        self.pass.as_ref().downcast_ref::<T>()
    }

    pub fn pass_mut<T>(&mut self) -> Option<&mut T>
    where
        T: AnalysisPass<P, S>, {
        self.pass.as_mut().downcast_mut::<T>()
    }

    pub fn state(&self) -> &S {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

// NOTE: AnalysisPass here will always be AnalysisPass<NoState>; this means that we
// cannot implement `as_group` or `as_group_mut` for `StatefulAnalysis` as it would
// require `S` to be `NoState` as well.
impl<P, S> AnalysisPass<P> for StatefulAnalysis<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    fn analyse(&mut self, project: &mut Project<P>) -> Result<(), AnalysisError> {
        self.pass.analyse_with(project, &mut self.state)
    }
}

pub struct OneShotAnalysis<P = InMemoryProvider, S = NoState>
where
    P: ProjectStorageProvider, {
    pass: Box<dyn AnalysisPass<P, S> + 'static>,
    executed: bool,
}

impl<P, S> OneShotAnalysis<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    pub fn new(pass: impl AnalysisPass<P, S> + 'static) -> Self {
        OneShotAnalysis {
            pass: Box::new(pass),
            executed: false,
        }
    }

    pub fn boxed_pass(&self) -> &BoxedAnalysisPass<P, S> {
        &self.pass
    }

    pub fn boxed_pass_mut(&mut self) -> &mut BoxedAnalysisPass<P, S> {
        &mut self.pass
    }

    pub fn pass<T>(&self) -> Option<&T>
    where
        T: AnalysisPass<P, S>, {
        self.pass.as_ref().downcast_ref::<T>()
    }

    pub fn pass_mut<T>(&mut self) -> Option<&mut T>
    where
        T: AnalysisPass<P, S>, {
        self.pass.as_mut().downcast_mut::<T>()
    }

    pub fn has_executed(&self) -> bool {
        self.executed
    }
}

impl<P, S> AnalysisPass<P, S> for OneShotAnalysis<P, S>
where
    P: ProjectStorageProvider,
    S: 'static,
{
    fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        if !self.executed {
            self.executed = true;
            self.pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<P, S>> {
        self.pass.as_group()
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<P, S>> {
        self.pass.as_group_mut()
    }
}

pub trait AnalysisPassExt<P, S>
where
    P: ProjectStorageProvider,
    S: 'static, {
    fn conditional(
        self,
        condition: impl AnalysisCondition<P, S> + 'static,
    ) -> ConditionalAnalysis<P, S>
    where
        Self: AnalysisPass<P, S> + Sized + 'static, {
        ConditionalAnalysis::new(self, condition)
    }

    fn iterated(self, condition: impl AnalysisCondition<P, S> + 'static) -> IteratedAnalysis<P, S>
    where
        Self: AnalysisPass<P, S> + Sized + 'static, {
        IteratedAnalysis::new(self, condition)
    }

    fn with_state(self, state: S) -> StatefulAnalysis<P, S>
    where
        Self: AnalysisPass<P, S> + Sized + 'static, {
        StatefulAnalysis::new(self, state)
    }

    fn one_shot(self) -> OneShotAnalysis<P, S>
    where
        Self: AnalysisPass<P, S> + Sized + 'static, {
        OneShotAnalysis::new(self)
    }
}

impl<P, S, T> AnalysisPassExt<P, S> for T
where
    T: AnalysisPass<P, S> + Sized + 'static,
    P: ProjectStorageProvider,
    S: 'static,
{
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_analysis_passes() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file("tests/ls.elf")?;

        let mut analyses = AnalysisManager::new();

        analyses.add_pass(
            "hello-world",
            |_project: &mut Project, _state: &mut NoState| {
                println!("Hello, world!");
                Ok(())
            },
        );

        let mut group = AnalysisGroup::new();

        group.add_pass(
            "bloop-step",
            |_project: &mut Project, _state: &mut NoState| {
                println!("Hello, world (step 1)!");
                Ok(())
            },
        );

        group.add_passes(
            "prefix",
            [
                |_project: &mut Project, state: &mut NoState| {
                    println!("Hello, world (step 2); state is {state:?}!");
                    Ok(())
                },
                |_project: &mut Project, state: &mut NoState| {
                    println!("Hello, world (step 3); state is {state:?}!");
                    Ok(())
                },
            ],
        );

        analyses.add_pass("basic-list-hello-world", group.iterated(3));

        analyses.add_pass(
            "cond-hello-world",
            AnalysisGroup::from_iter([
                |_project: &mut Project, state: &mut Vec<usize>| {
                    println!("Hello, world (step 1); state is {state:?}!");
                    let val = state.last().copied().unwrap_or(0);
                    state.push(val + 1);
                    Ok(())
                },
                |_project: &mut Project, state: &mut Vec<usize>| {
                    println!("Hello, world (step 2); state is {state:?}!");
                    let val = state.last().copied().unwrap_or(0);
                    state.push(val + 2);
                    Ok(())
                },
                |_project: &mut Project, state: &mut Vec<usize>| {
                    println!("Hello, world (step 3); state is {state:?}!");
                    let val = state.last().copied().unwrap_or(0);
                    state.push(val + 3);
                    Ok(())
                },
            ])
            .iterated(5)
            .with_state(Vec::new()),
        );

        analyses.analyse(&mut project, "hello-world")?;
        analyses.analyse(&mut project, "basic-list-hello-world")?;
        analyses.analyse(&mut project, "cond-hello-world")?;

        let g1 = analyses
            .get_boxed_pass("basic-list-hello-world")
            .unwrap()
            .as_group()
            .unwrap();

        for (name, _pass) in g1.passes() {
            println!("pass: {name}");
        }

        let g2 = analyses
            .get_boxed_pass("cond-hello-world")
            .unwrap()
            .as_group();

        // NOTE: here g2 will be None, because with_state erases the inner state type.

        assert!(g2.is_none());

        let mut analyses = AnalysisManager::<_, Vec<usize>>::new();

        analyses.add_pass(
            "cond-hello-world",
            AnalysisGroup::from_iter([
                |_project: &mut Project, state: &mut Vec<usize>| {
                    println!("Hello, world (step 1); state is {state:?}!");
                    let val = state.last().copied().unwrap_or(0);
                    state.push(val + 1);
                    Ok(())
                },
                |_project: &mut Project, state: &mut Vec<usize>| {
                    println!("Hello, world (step 2); state is {state:?}!");
                    let val = state.last().copied().unwrap_or(0);
                    state.push(val + 2);
                    Ok(())
                },
                |_project: &mut Project, state: &mut Vec<usize>| {
                    println!("Hello, world (step 3); state is {state:?}!");
                    let val = state.last().copied().unwrap_or(0);
                    state.push(val + 3);
                    Ok(())
                },
            ])
            .iterated(5),
        );

        analyses.analyse_with(&mut project, "cond-hello-world", &mut Vec::new())?;

        let g1 = analyses
            .get_boxed_pass("cond-hello-world")
            .unwrap()
            .as_group()
            .unwrap();

        for (name, _pass) in g1.passes() {
            assert!(name.starts_with("pass-"));
        }

        assert!(
            analyses
                .get_pass::<IteratedAnalysis<_, Vec<usize>>>("cond-hello-world")
                .is_some()
        );

        assert!(
            analyses
                .get_pass_mut::<IteratedAnalysis<_, Vec<usize>>>("cond-hello-world")
                .unwrap()
                .pass_mut::<AnalysisGroup<_, Vec<usize>>>()
                .is_some()
        );

        Ok(())
    }
}
