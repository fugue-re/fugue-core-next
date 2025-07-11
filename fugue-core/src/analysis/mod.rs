use std::borrow::Borrow;

use indexmap::IndexMap;
use thiserror::Error;
use uuid::Uuid;

use crate::project::Project;

pub mod core;

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("analysis pass forms a cyclic dependency: {0} -> {1}")]
    CyclicDependency(String, String),
    #[error("analysis pass not found: {0}")]
    PassNotFound(String),
    #[error("analysis pass failed: {0}")]
    PassFailed(String, anyhow::Error),
}

impl AnalysisError {
    pub fn pass_not_found(name: impl Into<String>) -> Self {
        AnalysisError::PassNotFound(name.into())
    }

    pub fn pass_failed<E>(name: impl Into<String>, error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        AnalysisError::PassFailed(name.into(), error.into())
    }
}

pub type NoState = ();
pub type BoxedAnalysisPass<'a, S = NoState> = Box<dyn AnalysisPass<'a, S> + 'a>;

pub struct AnalysisManager<'a, S = NoState> {
    passes: IndexMap<String, Box<dyn AnalysisPass<'a, S> + 'a>>,
}

impl<'a, S> AnalysisManager<'a, S> {
    pub fn new() -> Self {
        AnalysisManager {
            passes: IndexMap::new(),
        }
    }

    pub fn add_pass(&mut self, name: impl Into<String>, pass: impl AnalysisPass<'a, S> + 'a) {
        self.passes.insert(name.into(), Box::new(pass));
    }

    pub fn get_pass(&self, name: impl Borrow<str>) -> Option<&BoxedAnalysisPass<'a, S>> {
        self.passes.get(name.borrow())
    }

    pub fn get_pass_mut(
        &mut self,
        name: impl Borrow<str>,
    ) -> Option<&mut BoxedAnalysisPass<'a, S>> {
        self.passes.get_mut(name.borrow())
    }

    pub fn insert_after(
        &mut self,
        target: impl Borrow<str>,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, S> + 'a,
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
        pass: impl AnalysisPass<'a, S> + 'a,
    ) {
        let target = target.borrow();

        if let Some(index) = self.passes.get_index_of(target) {
            self.passes
                .insert_before(index, name.into(), Box::new(pass));
        } else {
            self.passes.insert(name.into(), Box::new(pass));
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &BoxedAnalysisPass<'a, S>)> {
        self.passes.iter().map(|(name, pass)| (name.as_ref(), pass))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&str, &mut BoxedAnalysisPass<'a, S>)> {
        self.passes
            .iter_mut()
            .map(move |(name, pass)| (name.as_ref(), pass))
    }

    pub fn passes(&self) -> impl Iterator<Item = (&str, &BoxedAnalysisPass<'a, S>)> {
        self.iter()
    }

    pub fn passes_mut(&mut self) -> impl Iterator<Item = (&str, &mut BoxedAnalysisPass<'a, S>)> {
        self.iter_mut()
    }

    pub fn analyse_with(
        &mut self,
        project: &mut Project,
        pass_name: impl Borrow<str>,
        state: &mut S,
    ) -> Result<(), AnalysisError> {
        let pass_name = pass_name.borrow();
        if let Some(pass) = self.passes.get_mut(pass_name) {
            pass.analyse_with(project, state)
        } else {
            Err(AnalysisError::PassNotFound(pass_name.to_string()))
        }
    }
}

impl<'a> AnalysisManager<'a> {
    pub fn analyse(&mut self, project: &mut Project, pass_name: &str) -> Result<(), AnalysisError> {
        self.analyse_with(project, pass_name, &mut Default::default())
    }
}

pub trait AnalysisPass<'a, S = NoState> {
    fn analyse(&mut self, #[allow(unused)] project: &mut Project) -> Result<(), AnalysisError> {
        unimplemented!(
            "either `AnalysisPass::analyse` or `AnalysisPass::analyse_with` must be implemented"
        )
    }

    fn analyse_with(
        &mut self,
        project: &mut Project,
        #[allow(unused)] state: &mut S,
    ) -> Result<(), AnalysisError> {
        self.analyse(project)
    }

    fn as_group(&self) -> Option<&AnalysisGroup<'a, S>> {
        None
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<'a, S>> {
        None
    }
}

impl<'a, S, F> AnalysisPass<'a, S> for F
where
    F: FnMut(&mut Project, &mut S) -> Result<(), AnalysisError> + 'a,
    S: 'a,
{
    fn analyse_with(&mut self, project: &mut Project, state: &mut S) -> Result<(), AnalysisError> {
        self(project, state)
    }
}

pub trait AnalysisCondition<'a, S> {
    fn evaluate(&mut self, state: &mut S) -> bool;
}

impl<'a, F, S> AnalysisCondition<'a, S> for F
where
    F: FnMut(&mut S) -> bool + 'a,
{
    fn evaluate(&mut self, state: &mut S) -> bool {
        self(state)
    }
}

impl<'a, S> AnalysisCondition<'a, S> for usize {
    fn evaluate(&mut self, _state: &mut S) -> bool {
        if let Some(nself) = self.checked_sub(1) {
            *self = nself;
            true
        } else {
            false
        }
    }
}

pub struct AnalysisGroup<'a, S = NoState> {
    passes: IndexMap<String, Box<dyn AnalysisPass<'a, S> + 'a>>,
}

impl<'a, S, P> FromIterator<P> for AnalysisGroup<'a, S>
where
    P: AnalysisPass<'a, S> + 'a,
{
    fn from_iter<T: IntoIterator<Item = P>>(iter: T) -> Self {
        let mut group = AnalysisGroup::new();
        group.add_passes("pass", iter);
        group
    }
}

impl<'a, S> AnalysisGroup<'a, S> {
    pub fn new() -> Self {
        AnalysisGroup {
            passes: IndexMap::new(),
        }
    }

    pub fn add_pass(&mut self, name: impl Into<String>, pass: impl AnalysisPass<'a, S> + 'a) {
        self.passes.insert(name.into(), Box::new(pass));
    }

    pub fn add_passes(
        &mut self,
        prefix: impl Into<String>,
        passes: impl IntoIterator<Item = impl AnalysisPass<'a, S> + 'a>,
    ) {
        let prefix = prefix.into();
        self.passes.extend(passes.into_iter().map(|pass| {
            let name = format!("{prefix}-{}", Uuid::now_v7().as_hyphenated());
            (name, Box::new(pass) as Box<dyn AnalysisPass<'a, S>>)
        }));
    }

    pub fn get_pass(&self, name: impl Borrow<str>) -> Option<&BoxedAnalysisPass<'a, S>> {
        self.passes.get(name.borrow())
    }

    pub fn get_pass_mut(
        &mut self,
        name: impl Borrow<str>,
    ) -> Option<&mut BoxedAnalysisPass<'a, S>> {
        self.passes.get_mut(name.borrow())
    }

    pub fn insert_after(
        &mut self,
        target: impl Borrow<str>,
        name: impl Into<String>,
        pass: impl AnalysisPass<'a, S> + 'a,
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
        pass: impl AnalysisPass<'a, S> + 'a,
    ) {
        let target = target.borrow();

        if let Some(index) = self.passes.get_index_of(target) {
            self.passes
                .insert_before(index, name.into(), Box::new(pass));
        } else {
            self.passes.insert(name.into(), Box::new(pass));
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &BoxedAnalysisPass<'a, S>)> {
        self.passes.iter().map(|(name, pass)| (name.as_ref(), pass))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&str, &mut BoxedAnalysisPass<'a, S>)> {
        self.passes
            .iter_mut()
            .map(move |(name, pass)| (name.as_ref(), pass))
    }

    pub fn passes(&self) -> impl Iterator<Item = (&str, &BoxedAnalysisPass<'a, S>)> {
        self.iter()
    }

    pub fn passes_mut(&mut self) -> impl Iterator<Item = (&str, &mut BoxedAnalysisPass<'a, S>)> {
        self.iter_mut()
    }
}

impl<'a, S> AnalysisPass<'a, S> for AnalysisGroup<'a, S> {
    fn analyse_with(&mut self, project: &mut Project, state: &mut S) -> Result<(), AnalysisError> {
        for pass in self.passes.values_mut() {
            pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<'a, S>> {
        Some(self)
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<'a, S>> {
        Some(self)
    }
}

pub struct IteratedAnalysis<'a, S = NoState> {
    pass: Box<dyn AnalysisPass<'a, S> + 'a>,
    condition: Box<dyn AnalysisCondition<'a, S> + 'a>,
}

impl<'a, S> IteratedAnalysis<'a, S> {
    pub fn new(
        pass: impl AnalysisPass<'a, S> + 'a,
        condition: impl AnalysisCondition<'a, S> + 'a,
    ) -> Self {
        IteratedAnalysis {
            pass: Box::new(pass),
            condition: Box::new(condition),
        }
    }
}

impl<'a, S> AnalysisPass<'a, S> for IteratedAnalysis<'a, S> {
    fn analyse_with(&mut self, project: &mut Project, state: &mut S) -> Result<(), AnalysisError> {
        while self.condition.evaluate(state) {
            self.pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<'a, S>> {
        self.pass.as_group()
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<'a, S>> {
        self.pass.as_group_mut()
    }
}

pub struct ConditionalAnalysis<'a, S = NoState> {
    pass: Box<dyn AnalysisPass<'a, S> + 'a>,
    condition: Box<dyn AnalysisCondition<'a, S> + 'a>,
}

impl<'a, S> ConditionalAnalysis<'a, S> {
    pub fn new(
        pass: impl AnalysisPass<'a, S> + 'a,
        condition: impl AnalysisCondition<'a, S> + 'a,
    ) -> Self {
        ConditionalAnalysis {
            pass: Box::new(pass),
            condition: Box::new(condition),
        }
    }
}

impl<'a, S> AnalysisPass<'a, S> for ConditionalAnalysis<'a, S> {
    fn analyse_with(&mut self, project: &mut Project, state: &mut S) -> Result<(), AnalysisError> {
        if self.condition.evaluate(state) {
            self.pass.analyse_with(project, state)?;
        }
        Ok(())
    }

    fn as_group(&self) -> Option<&AnalysisGroup<'a, S>> {
        self.pass.as_group()
    }

    fn as_group_mut(&mut self) -> Option<&mut AnalysisGroup<'a, S>> {
        self.pass.as_group_mut()
    }
}

pub struct StatefulAnalysis<'a, S = NoState> {
    pass: Box<dyn AnalysisPass<'a, S> + 'a>,
    state: S,
}

impl<'a, S> StatefulAnalysis<'a, S> {
    pub fn new(pass: impl AnalysisPass<'a, S> + 'a, state: S) -> Self {
        StatefulAnalysis {
            pass: Box::new(pass),
            state,
        }
    }
}

// NOTE: AnalysisPass here will always be AnalysisPass<NoState>; this means that we
// cannot implement `as_group` or `as_group_mut` for `StatefulAnalysis` as it would
// require `S` to be `NoState` as well.
impl<'a, S> AnalysisPass<'a> for StatefulAnalysis<'a, S> {
    fn analyse(&mut self, project: &mut Project) -> Result<(), AnalysisError> {
        self.pass.analyse_with(project, &mut self.state)
    }
}

pub trait AnalysisPassExt<'a, S> {
    fn conditional(
        self,
        condition: impl AnalysisCondition<'a, S> + 'a,
    ) -> ConditionalAnalysis<'a, S>
    where
        Self: AnalysisPass<'a, S> + Sized + 'a,
    {
        ConditionalAnalysis::new(self, condition)
    }

    fn iterated(self, condition: impl AnalysisCondition<'a, S> + 'a) -> IteratedAnalysis<'a, S>
    where
        Self: AnalysisPass<'a, S> + Sized + 'a,
    {
        IteratedAnalysis::new(self, condition)
    }

    fn with_state(self, state: S) -> StatefulAnalysis<'a, S>
    where
        Self: AnalysisPass<'a, S> + Sized + 'a,
    {
        StatefulAnalysis::new(self, state)
    }
}

impl<'a, S, P> AnalysisPassExt<'a, S> for P where P: AnalysisPass<'a, S> + Sized + 'a {}

#[cfg(test)]
mod test {
    use crate::storage::TransientStorageProvider;

    use super::*;

    #[test]
    fn test_analysis_passes() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file::<TransientStorageProvider>("tests/ls.elf")?;
        let mut my_mut = 0;
        let mut my_beep = 2;

        let mut analyses = AnalysisManager::new();

        pub struct Simple<'a> {
            my_mut: &'a mut usize,
        }

        impl<'a> AnalysisPass<'a, NoState> for Simple<'a> {
            fn analyse(&mut self, _project: &mut Project) -> Result<(), AnalysisError> {
                println!("Hello, world; {}!", self.my_mut);
                *self.my_mut += 1;
                Ok(())
            }
        }

        analyses.add_pass(
            "hello-world",
            |_project: &mut Project, _state: &mut NoState| {
                println!("Hello, world!");
                Ok(())
            },
        );

        analyses.add_pass(
            "simple",
            Simple {
                my_mut: &mut my_mut,
            }
            .iterated(10),
        );

        let mut group = AnalysisGroup::new();

        group.add_pass(
            "bloop-step",
            |_project: &mut Project, _state: &mut NoState| {
                let my_bloop = &mut my_beep;
                println!("Hello, world (step 1); {my_bloop}!");
                *my_bloop += 1;
                Ok(())
            },
        );

        group.add_passes(
            "prefix",
            [
                |_project: &mut Project, state: &mut NoState| {
                    {
                        println!("Hello, world (step 2); state is {state:?}!");
                        Ok(())
                    }
                    .into()
                },
                |_project: &mut Project, state: &mut NoState| {
                    {
                        println!("Hello, world (step 3); state is {state:?}!");
                        Ok(())
                    }
                    .into()
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
        analyses.analyse(&mut project, "simple")?;
        analyses.analyse(&mut project, "basic-list-hello-world")?;
        analyses.analyse(&mut project, "cond-hello-world")?;

        let g1 = analyses
            .get_pass("basic-list-hello-world")
            .unwrap()
            .as_group()
            .unwrap();

        for (name, _pass) in g1.passes() {
            println!("pass: {name}");
        }

        let g2 = analyses.get_pass("cond-hello-world").unwrap().as_group();

        // NOTE: here g2 will be None, because with_state erases the inner state type.

        assert!(g2.is_none());

        let mut analyses = AnalysisManager::<Vec<usize>>::new();

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
            .get_pass("cond-hello-world")
            .unwrap()
            .as_group()
            .unwrap();

        for (name, _pass) in g1.passes() {
            assert!(name.starts_with("pass-"));
        }

        Ok(())
    }
}
