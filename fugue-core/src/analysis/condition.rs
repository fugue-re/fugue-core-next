pub trait AnalysisCondition<S>: Send {
    fn evaluate(&mut self, state: &mut S) -> bool;
}

impl<F, S> AnalysisCondition<S> for F
where
    F: FnMut(&mut S) -> bool + Send,
{
    fn evaluate(&mut self, state: &mut S) -> bool {
        self(state)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IterationLimit(usize);

impl IterationLimit {
    pub fn new(iterations: usize) -> Self {
        Self(iterations)
    }
}

impl<S> AnalysisCondition<S> for IterationLimit {
    fn evaluate(&mut self, _state: &mut S) -> bool {
        if let Some(remaining) = self.0.checked_sub(1) {
            self.0 = remaining;
            true
        } else {
            false
        }
    }
}
