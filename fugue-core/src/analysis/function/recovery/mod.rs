use thiserror::Error;

use crate::analysis::AnalysisError;
use crate::ir::{Address, IncompleteCodeBlockId, InsnError, InsnId, ProblemKind};
use crate::lifter::{DisassemblerError, InsnResolverError, LifterError};
use crate::storage::SegmentStorageError;

pub(crate) mod analysis;
pub(crate) use analysis::FUNCTION_RECOVERY_ANALYSER;
pub use analysis::{
    FunctionDiscoveryContext, FunctionRecovery, FunctionRecoveryExtension,
    FunctionStructuringContext,
};

pub(crate) mod builder;
pub use builder::{FunctionBuilder, FunctionBuilderContext, FunctionRecoveryState};

pub(crate) mod hooks;
pub use hooks::{FunctionRecoveryCommitContext, FunctionRecoveryCommitHook};

pub(crate) mod patterns;
pub use patterns::{FunctionRecoveryPatternMatcher, FunctionRecoveryPatternMatcherError};

mod structuring;

pub const DEFAULT_MAX_BLOCK_INSNS: usize = u16::MAX as usize;
pub const DEFAULT_MAX_FUNCTION_BLOCKS: usize = u16::MAX as usize;
pub const DEFAULT_MAX_FUNCTION_INSNS: usize = u16::MAX as usize;
pub(super) const FUNCTION_RECOVERY_BLOCKING_PROBLEMS: [ProblemKind; 7] = [
    ProblemKind::HinderedByAssertedFact,
    ProblemKind::AvoidedBytes,
    ProblemKind::CannotCreateFunction,
    ProblemKind::DecodeFailed,
    ProblemKind::FunctionTooLarge,
    ProblemKind::PassFailed,
    ProblemKind::Unknown,
];

#[derive(Debug, Error)]
pub enum FunctionRecoveryError {
    #[error("commit hook failed: {0}")]
    CommitHook(AnalysisError),
    #[error(transparent)]
    Disassembly(#[from] DisassemblerError),
    #[error("initialisation pass failed: {0}")]
    InitialisationPass(AnalysisError),
    #[error(transparent)]
    Insn(#[from] InsnError),
    #[error("invalid block id: {0:?}")]
    InvalidBlockId(IncompleteCodeBlockId),
    #[error(
        "invalid block at {address}; instruction count ({insn_count}) must be non-zero and less than {maximum_insn_count}"
    )]
    InvalidBlockInsnCount {
        address: Address,
        insn_count: usize,
        maximum_insn_count: usize,
    },
    #[error("invalid block size at {address}: {size} bytes exceeds u16 capacity")]
    InvalidBlockSize { address: Address, size: usize },
    #[error("invalid function; failed to lift any instructions")]
    InvalidFunction,
    #[error(
        "invalid function at {address}; block count ({block_count}) must be less than {maximum_block_count}"
    )]
    InvalidFunctionBlockCount {
        address: Address,
        block_count: usize,
        maximum_block_count: usize,
    },
    #[error(
        "invalid function at {address}; instruction count ({insn_count}) exceeds limit ({maximum_insn_count})"
    )]
    InvalidFunctionInsnCount {
        address: Address,
        insn_count: usize,
        maximum_insn_count: usize,
    },
    #[error("invalid insn id: {0:?}")]
    InvalidInsnId(InsnId),
    #[error(transparent)]
    Lifting(#[from] LifterError),
    #[error("post-structuring pass failed: {0}")]
    PostStructuringPass(AnalysisError),
    #[error(transparent)]
    SegmentStorage(#[from] SegmentStorageError),
}

impl FunctionRecoveryError {
    pub fn invalid_block_id(id: IncompleteCodeBlockId) -> Self {
        FunctionRecoveryError::InvalidBlockId(id)
    }

    pub fn invalid_block_size(address: Address, size: usize) -> Self {
        Self::InvalidBlockSize { address, size }
    }

    pub fn invalid_block_insn_count(
        address: Address,
        insn_count: usize,
        maximum_insn_count: usize,
    ) -> Self {
        Self::InvalidBlockInsnCount {
            address,
            insn_count,
            maximum_insn_count,
        }
    }

    pub fn invalid_function_block_count(
        address: Address,
        block_count: usize,
        maximum_block_count: usize,
    ) -> Self {
        Self::InvalidFunctionBlockCount {
            address,
            block_count,
            maximum_block_count,
        }
    }

    pub fn invalid_function_insn_count(
        address: Address,
        insn_count: usize,
        maximum_insn_count: usize,
    ) -> Self {
        Self::InvalidFunctionInsnCount {
            address,
            insn_count,
            maximum_insn_count,
        }
    }

    pub fn invalid_insn_id(id: InsnId) -> Self {
        Self::InvalidInsnId(id)
    }

    pub fn problem_kind(&self) -> ProblemKind {
        match self {
            Self::CommitHook(_) | Self::InitialisationPass(_) | Self::PostStructuringPass(_) => {
                ProblemKind::PassFailed
            }
            Self::Disassembly(_) | Self::Insn(_) | Self::Lifting(_) => ProblemKind::DecodeFailed,
            Self::InvalidBlockSize { .. }
            | Self::InvalidBlockInsnCount { .. }
            | Self::InvalidFunctionInsnCount { .. }
            | Self::InvalidFunctionBlockCount { .. } => ProblemKind::FunctionTooLarge,
            Self::InvalidFunction => ProblemKind::CannotCreateFunction,
            Self::InvalidBlockId(_) | Self::InvalidInsnId(_) => ProblemKind::Unknown,
            Self::SegmentStorage(_) => ProblemKind::AvoidedBytes,
        }
    }
}

impl From<InsnResolverError> for FunctionRecoveryError {
    fn from(error: InsnResolverError) -> Self {
        match error {
            InsnResolverError::Disassembly(error) => Self::Disassembly(error),
            InsnResolverError::Insn(error) => Self::Insn(error),
            InsnResolverError::Lifting(error) => Self::Lifting(error),
        }
    }
}

// NOTE: we use the following conventions for function recovery configuration:
// - If an option is a flag (boolean), then we use `enable_<option>` to set it and
//   `with_<option>` to create a new config with the option set.
// - If an option is a value (e.g., usize), then we use `set_<option>` to set it and
//   `with_<option>` to create a new config with the option set.
// - For accessors, we use the option name directly (e.g., `max_function_blocks()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionRecoveryConfig {
    // This flag controls whether to automatically commit remaining pending functions after
    // all candidates have been processed and no further analysis is possible.
    commit_pending_functions: bool,
    // This value controls the maximum number of basic blocks allowed in a single function.
    max_function_blocks: usize,
    // This value controls the maximum number of instructions allowed in a single function.
    max_function_insns: usize,
    // This value controls the maximum number of instructions allowed in a single basic block.
    max_block_insns: usize,
    // This flag controls whether to use fine-grained block coverage when computing function
    // coverage and gaps during recovery. We consider fine-grained block coverage to be coverage
    // tracked at the level of individual blocks, rather than at the function level, i.e., whether
    // to track the coverage of a function based on block bounds or by the minimum and maximum
    // addresses of the function's blocks.
    use_fine_grained_block_coverage: bool,
    // This flag controls whether to identify non-returning functions during recovery, and to
    // suppress the fall-through of calls that target them.
    use_non_returning_analysis: bool,
    // This flag controls whether to use segment function hints when recovering functions.
    use_segment_function_hints: bool,
    // This flag controls whether to use segment mapping hints when recovering functions.
    use_segment_mapping_hints: bool,
    // This flag controls whether to use symbol table function hints when recovering functions.
    use_symbol_table_function_hints: bool,
    use_switch_analysis: bool,
}

impl Default for FunctionRecoveryConfig {
    fn default() -> Self {
        FunctionRecoveryConfig {
            commit_pending_functions: true,
            max_function_blocks: DEFAULT_MAX_FUNCTION_BLOCKS,
            max_function_insns: DEFAULT_MAX_FUNCTION_INSNS,
            max_block_insns: DEFAULT_MAX_BLOCK_INSNS,
            use_fine_grained_block_coverage: false,
            use_non_returning_analysis: false,
            use_segment_function_hints: true,
            use_segment_mapping_hints: true,
            use_symbol_table_function_hints: true,
            use_switch_analysis: false,
        }
    }
}

impl FunctionRecoveryConfig {
    pub fn commit_pending_functions(&self) -> bool {
        self.commit_pending_functions
    }

    pub fn enable_commit_pending_functions(&mut self, enabled: bool) {
        self.commit_pending_functions = enabled;
    }

    pub fn with_commit_pending_functions(mut self, enabled: bool) -> Self {
        self.enable_commit_pending_functions(enabled);
        self
    }

    pub fn max_function_blocks(&self) -> usize {
        self.max_function_blocks
    }

    pub fn set_max_function_blocks(&mut self, max: usize) {
        self.max_function_blocks = max.clamp(1, DEFAULT_MAX_FUNCTION_BLOCKS);
    }

    pub fn with_max_function_blocks(mut self, max: usize) -> Self {
        self.set_max_function_blocks(max);
        self
    }

    pub fn max_function_insns(&self) -> usize {
        self.max_function_insns
    }

    pub fn set_max_function_insns(&mut self, max: usize) {
        self.max_function_insns = max.clamp(1, DEFAULT_MAX_FUNCTION_INSNS);
    }

    pub fn with_max_function_insns(mut self, max: usize) -> Self {
        self.set_max_function_insns(max);
        self
    }

    pub fn max_block_insns(&self) -> usize {
        self.max_block_insns
    }

    pub fn set_max_block_insns(&mut self, max: usize) {
        self.max_block_insns = max.clamp(1, DEFAULT_MAX_BLOCK_INSNS);
    }

    pub fn with_max_block_insns(mut self, max: usize) -> Self {
        self.set_max_block_insns(max);
        self
    }

    pub fn use_fine_grained_block_coverage(&self) -> bool {
        self.use_fine_grained_block_coverage
    }

    pub fn enable_fine_grained_block_coverage(&mut self, enabled: bool) {
        self.use_fine_grained_block_coverage = enabled;
    }

    pub fn with_fine_grained_block_coverage(mut self, enabled: bool) -> Self {
        self.enable_fine_grained_block_coverage(enabled);
        self
    }

    pub fn use_segment_function_hints(&self) -> bool {
        self.use_segment_function_hints
    }

    pub fn enable_segment_function_hints(&mut self, enabled: bool) {
        self.use_segment_function_hints = enabled;
    }

    pub fn with_segment_function_hints(mut self, enabled: bool) -> Self {
        self.enable_segment_function_hints(enabled);
        self
    }

    pub fn use_segment_mapping_hints(&self) -> bool {
        self.use_segment_mapping_hints
    }

    pub fn enable_segment_mapping_hints(&mut self, enabled: bool) {
        self.use_segment_mapping_hints = enabled;
    }

    pub fn with_segment_mapping_hints(mut self, enabled: bool) -> Self {
        self.enable_segment_mapping_hints(enabled);
        self
    }

    pub fn use_non_returning_analysis(&self) -> bool {
        self.use_non_returning_analysis
    }

    pub fn enable_non_returning_analysis(&mut self, enabled: bool) {
        self.use_non_returning_analysis = enabled;
    }

    pub fn with_non_returning_analysis(mut self, enabled: bool) -> Self {
        self.enable_non_returning_analysis(enabled);
        self
    }

    pub fn use_switch_analysis(&self) -> bool {
        self.use_switch_analysis
    }

    pub fn enable_switch_analysis(&mut self, enabled: bool) {
        self.use_switch_analysis = enabled;
    }

    pub fn with_switch_analysis(mut self, enabled: bool) -> Self {
        self.enable_switch_analysis(enabled);
        self
    }

    pub fn use_symbol_table_function_hints(&self) -> bool {
        self.use_symbol_table_function_hints
    }

    pub fn enable_symbol_table_function_hints(&mut self, enabled: bool) {
        self.use_symbol_table_function_hints = enabled;
    }

    pub fn with_symbol_table_function_hints(mut self, enabled: bool) -> Self {
        self.enable_symbol_table_function_hints(enabled);
        self
    }
}

#[cfg(test)]
mod test {
    use tracing_subscriber::filter::EnvFilter;
    use tracing_subscriber::fmt::format::FmtSpan;

    use crate::loader::{Loadable, LoadableAnalysers, Loader, Shellcode};
    use crate::project::Project;

    #[test]
    #[ignore = "requires local language data and binary fixtures"]
    fn test_control_flow_recovery_ls() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let loader = Loader::from_file("tests/ls.elf")?;
            let mut project = Project::new_transient(&loader)?;
            let mut cfr = loader.analysers().function_recovery()?;

            cfr.add_candidate(0x4da0u64);
            cfr.add_candidate(0x6dd0u64);
            cfr.analyse(&mut project)?;

            Ok(())
        })
    }

    #[test]
    #[ignore = "requires FUGUE_LANGUAGE_DIR"]
    fn test_control_flow_recovery_overlap() -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(FmtSpan::CLOSE)
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

            let loader = Shellcode::new("x86:LE:64", 0x4EB14u64, &shellcode)?;
            let mut project = Project::new_transient(&loader)?;
            let mut cfr = loader.analysers().function_recovery()?;

            cfr.add_candidate(0x4EB14u64);
            cfr.analyse(&mut project)?;

            Ok(())
        })
    }
}
