mod analyser;
mod work;

pub(crate) use analyser::ScheduledAnalyser;
pub(crate) use work::{
    AnalysisWorkQueue, Degradation, DegradationReport, WORK_SLICE_BYTES, WorkBatch,
};
