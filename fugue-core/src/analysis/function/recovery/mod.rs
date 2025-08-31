use thiserror::Error;

use crate::analysis::AnalysisError;
use crate::lifter::LifterError;
use crate::storage::{EntityStorageError, SegmentStorageError};

pub mod translator;
pub mod types;

#[derive(Debug, Error)]
pub enum FunctionBuilderError {
    #[error("initialisation pass failed: {0}")]
    InitialisationPass(AnalysisError),
    #[error("post-lifting pass failed: {0}")]
    PostLiftingPass(AnalysisError),
    #[error("failed to lift any instructions")]
    NoInstructions,
    #[error("failed to create function; number of blocks ({0}) exceeds limit ({1})")]
    ExceededBlockLimit(usize, usize),
    #[error(transparent)]
    Lifter(#[from] LifterError),
    #[error("failed persist function: {0}")]
    EntityStorage(#[from] EntityStorageError),
    #[error(transparent)]
    SegmentStorage(#[from] SegmentStorageError),
    #[error("invalid block index: {0}")]
    InvalidBlockId(usize),
    #[error("invalid instruction index: {0}")]
    InvalidInstructionId(usize),
}
