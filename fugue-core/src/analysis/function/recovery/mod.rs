use thiserror::Error;

use crate::analysis::AnalysisError;
use crate::ir::Address;
use crate::lifter::{DisassemblerError, LifterError};
use crate::storage::SegmentStorageError;

pub mod analysis;
pub use analysis::FunctionRecovery;

pub mod builder;
pub use builder::{FunctionBuilder, FunctionBuilderContext, PartialFunctionWithContext};

pub mod ir;
pub use ir::{InsnEntry, PartialCodeBlock, PartialFunction};

pub mod translator;
pub use translator::Translator;

pub const DEFAULT_MAX_BLOCK_SIZE: usize = u16::MAX as usize;
pub const DEFAULT_MAX_FUNCTION_SIZE: usize = u16::MAX as usize;

#[derive(Debug, Error)]
pub enum FunctionRecoveryError {
    // analysis pass errors
    #[error("initialisation pass failed: {0}")]
    InitialisationPass(AnalysisError),
    #[error("post-lifting pass failed: {0}")]
    PostLiftingPass(AnalysisError),
    // creation issues due to table invariants or storage
    #[error("failed to create block: {0}")]
    BlockCreation(anyhow::Error),
    #[error("failed to create function: {0}")]
    FunctionCreation(anyhow::Error),
    // translation and I/O errors
    #[error(transparent)]
    Disassembly(#[from] DisassemblerError),
    #[error(transparent)]
    Lifting(#[from] LifterError),
    #[error(transparent)]
    SegmentStorage(#[from] SegmentStorageError),
    // invariant violations
    #[error("invalid function; failed to lift any instructions")]
    InvalidFunction,
    #[error("invalid function at {0}; number of blocks ({1}) must be less than {2}")]
    InvalidFunctionSize(Address, usize, usize),
    #[error("invalid block index: {0}")]
    InvalidBlockId(usize),
    #[error(
        "invalid block size at {0}; number of instructions ({1}) must be non-zero and less than {2}"
    )]
    InvalidBlockSize(Address, usize, usize),
    #[error("invalid instruction index: {0}")]
    InvalidInstructionId(usize),
}

impl FunctionRecoveryError {
    pub fn block_creation<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        FunctionRecoveryError::BlockCreation(err.into())
    }

    pub fn function_creation<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        FunctionRecoveryError::FunctionCreation(err.into())
    }

    pub fn invalid_block_size(addr: Address, num_insns: usize, max_insns: usize) -> Self {
        FunctionRecoveryError::InvalidBlockSize(addr, num_insns, max_insns)
    }

    pub fn invalid_function_size(addr: Address, num_blocks: usize, max_blocks: usize) -> Self {
        FunctionRecoveryError::InvalidFunctionSize(addr, num_blocks, max_blocks)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionRecoveryConfig {
    max_function_blocks: usize,
    max_block_insns: usize,
}

impl Default for FunctionRecoveryConfig {
    fn default() -> Self {
        FunctionRecoveryConfig {
            max_function_blocks: DEFAULT_MAX_FUNCTION_SIZE,
            max_block_insns: DEFAULT_MAX_BLOCK_SIZE,
        }
    }
}

impl FunctionRecoveryConfig {
    pub fn max_function_blocks(&self) -> usize {
        self.max_function_blocks
    }

    pub fn max_block_insns(&self) -> usize {
        self.max_block_insns
    }

    pub fn set_max_function_blocks(&mut self, max: usize) {
        self.max_function_blocks = max.min(DEFAULT_MAX_FUNCTION_SIZE).max(1);
    }

    pub fn with_max_function_blocks(mut self, max: usize) -> Self {
        self.set_max_function_blocks(max);
        self
    }

    pub fn set_max_block_insns(&mut self, max: usize) {
        self.max_block_insns = max.min(DEFAULT_MAX_BLOCK_SIZE).max(1);
    }

    pub fn with_max_block_insns(mut self, max: usize) -> Self {
        self.set_max_block_insns(max);
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::analysis::AnalysisPass;
    use crate::loader::Shellcode;
    use crate::project::InMemoryProject;

    #[test]
    fn test_control_flow_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut project = InMemoryProject::from_file("tests/ls.elf")?;
            let mut cfr = FunctionRecovery::new();

            cfr.add_candidate(0x4da0u64);
            cfr.add_candidate(0x6dd0u64);
            cfr.analyse(&mut project)?;

            Ok(())
        })
    }

    #[test]
    fn test_control_flow_recovery_overlap() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let shellcode = [
                0x55, 0x8B, 0xEC, 0x51, 0x51, 0x56, 0x8B, 0x75, 0x0C, 0x57, 0x33, 0xFF, 0x39, 0x3D,
                0x6C, 0x50, 0x40, 0x00, 0x75, 0x26, 0x56, 0xFF, 0x75, 0x08, 0x68, 0x18, 0x12, 0x40,
                0x00, 0xFF, 0x15, 0xF0, 0x10, 0x40, 0x00, 0x85, 0xC0, 0x74, 0x13, 0x68, 0xE0, 0x12,
                0x40, 0x00, 0xFF, 0x75, 0x08, 0xFF, 0x15, 0xEC, 0x10, 0x40, 0x00, 0x33, 0xC0, 0x40,
                0xEB, 0x43, 0x8D, 0x45, 0x0C, 0x50, 0x68, 0x28, 0x13, 0x40, 0x00, 0x68, 0x02, 0x00,
                0x00, 0x80, 0xFF, 0x15, 0x08, 0x10, 0x40, 0x00, 0x85, 0xC0, 0x75, 0x29, 0x8D, 0x45,
                0xFC, 0x50, 0xFF, 0x75, 0x08, 0x8D, 0x45, 0xF8, 0x50, 0x57, 0x57, 0xFF, 0x75, 0x0C,
                0x89, 0x75, 0xFC, 0xFF, 0x15, 0x00, 0x10, 0x40, 0x00, 0x85, 0xC0, 0x75, 0x03, 0x33,
                0xFF, 0x47, 0xFF, 0x75, 0x0C, 0xFF, 0x15, 0x24, 0x10, 0x40, 0x00, 0x8B, 0xC7, 0x5F,
                0x5E, 0xC9, 0xC2, 0x08, 0x00,
            ];

            let mut project =
                InMemoryProject::new(&Shellcode::new("x86:LE:64", 0x4EB14u64, &shellcode)?)?;
            let mut cfr = FunctionRecovery::new();

            cfr.add_candidate(0x4EB14u64);
            cfr.analyse(&mut project)?;

            Ok(())
        })
    }
}
