mod analyser;
mod work;

pub(crate) use analyser::{IlAnalyserAdapter, IlAnalysisInputs, ScheduledAnalyser};
pub(crate) use work::{
    AnalysisWorkQueue, Degradation, DegradationReport, WORK_SLICE_BYTES, WorkBatch,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AnalyserId(usize);

impl AnalyserId {
    pub(crate) const fn new(index: usize) -> Self {
        Self(index)
    }

    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AnalyserOrder(u32);

impl AnalyserOrder {
    pub(crate) const fn new(order: u32) -> Self {
        Self(order)
    }
}
