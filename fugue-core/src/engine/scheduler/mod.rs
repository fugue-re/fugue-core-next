mod analyser;
mod work;

pub use analyser::IlAnalyserAdapter;
pub(crate) use analyser::{IlAnalysisInputs, ScheduledAnalyser};
pub(crate) use work::{
    AnalysisWorkQueue, Degradation, DegradationReport, WORK_SLICE_BYTES, WorkBatch,
};
