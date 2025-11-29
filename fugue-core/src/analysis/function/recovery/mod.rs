use thiserror::Error;

use crate::analysis::AnalysisError;
use crate::ir::Address;
use crate::lifter::{DisassemblerError, LifterError};
use crate::storage::{EntityStorageError, SegmentStorageError};

pub mod analysis;

pub mod builder;
pub use builder::{FunctionBuilder, FunctionBuilderContext, PartialFunctionWithContext};

pub mod ir;
pub use ir::{InsnEntry, PartialCodeBlock, PartialFunction};

pub mod translator;
pub use translator::Translator;

#[derive(Debug, Error)]
pub enum FunctionRecoveryError {
    #[error("initialisation pass failed: {0}")]
    InitialisationPass(AnalysisError),
    #[error("post-lifting pass failed: {0}")]
    PostLiftingPass(AnalysisError),
    #[error("failed to lift any instructions")]
    NoInstructions,
    #[error("failed to create function; number of blocks ({0}) exceeds limit ({1})")]
    ExceededBlockLimit(usize, usize),
    #[error(transparent)]
    Disassembly(#[from] DisassemblerError),
    #[error(transparent)]
    Lifting(#[from] LifterError),
    #[error("failed persist function: {0}")]
    EntityStorage(#[from] EntityStorageError),
    #[error(transparent)]
    SegmentStorage(#[from] SegmentStorageError),
    #[error("invalid block index: {0}")]
    InvalidBlockId(usize),
    #[error("invalid block size at {0} ({1}); must be non-zero and less than 65536")]
    InvalidBlockSize(Address, usize),
    #[error("invalid instruction index: {0}")]
    InvalidInstructionId(usize),
}

pub struct FunctionRecoveryConfig {
    pub max_blocks: usize,
}

impl Default for FunctionRecoveryConfig {
    fn default() -> Self {
        FunctionRecoveryConfig {
            max_blocks: 0x10000,
        }
    }
}
