use thiserror::Error;

use crate::analysis::AnalysisError;
use crate::ir::{Address, IncompleteCodeBlockId, InsnError, InsnId, ProblemKind};
use crate::lifter::{DisassemblerError, InsnResolverError, LifterError};
use crate::storage::SegmentStorageError;

pub(crate) mod analysis;
pub(crate) use analysis::FUNCTION_RECOVERY_ANALYSER;
pub use analysis::{
    FunctionDiscoveryContext, FunctionDiscoveryRanges, FunctionRecovery, FunctionRecoveryExtension,
    InterFunctionStructuringContext,
};

pub(crate) mod builder;
pub use builder::{FunctionBuilderContext, StructuredFunctionContext};

mod executor;

pub(crate) mod hooks;
pub use hooks::{FunctionCommitContext, FunctionCommitPolicy};

pub(crate) mod patterns;
pub use patterns::{FunctionRecoveryPatternMatcher, FunctionRecoveryPatternMatcherError};

mod structuring;

const MAX_BLOCK_INSN_COUNT: usize = u16::MAX as usize;
const MAX_FUNCTION_BLOCK_COUNT: usize = u16::MAX as usize;
const MAX_FUNCTION_INSN_COUNT: usize = u16::MAX as usize;

const DEFAULT_INVOCATION_CANDIDATE_LIMIT: usize = 8192;
const DEFAULT_INVOCATION_FUNCTION_LIMIT: usize = 8192;
const DEFAULT_INVOCATION_OUTPUT_BYTE_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FunctionRecoveryError {
    #[error("commit policy failed: {0}")]
    CommitPolicy(AnalysisError),
    #[error(transparent)]
    Disassembly(#[from] DisassemblerError),
    #[error("pre-resolution pass failed: {0}")]
    PreResolutionPass(AnalysisError),
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
            Self::CommitPolicy(_) | Self::PreResolutionPass(_) | Self::PostStructuringPass(_) => {
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
    // This value controls the maximum number of candidate functions that can be processed in a
    // single invocation of the function recovery analyser.
    max_candidates_per_invocation: usize,
    // This value controls the maximum number of functions that can be recovered in a single
    // invocation of the function recovery analyser.
    max_functions_per_invocation: usize,
    // This value controls the maximum number of bytes that can be output in a single invocation
    // of the function recovery analyser.
    max_output_bytes_per_invocation: usize,
    // This flag controls whether to use fine-grained block coverage when computing function
    // coverage and gaps during recovery. We consider fine-grained block coverage to be coverage
    // tracked at the level of individual blocks, rather than at the function level, i.e., whether
    // to track the coverage of a function based on block bounds or by the minimum and maximum
    // addresses of the function's blocks.
    fine_grained_block_coverage: bool,
    // This flag controls whether to identify non-returning functions during recovery, and to
    // suppress the fall-through of calls that target them.
    non_returning_analysis: bool,
    // This flag controls whether to use segment function hints when recovering functions.
    segment_function_hints: bool,
    // This flag controls whether to use segment mapping hints when recovering functions.
    segment_mapping_hints: bool,
    // This flag controls whether to use symbol table function hints when recovering functions.
    symbol_table_function_hints: bool,
    // This flag controls whether to perform switch analysis during function recovery.
    switch_analysis: bool,
}

impl Default for FunctionRecoveryConfig {
    fn default() -> Self {
        FunctionRecoveryConfig {
            commit_pending_functions: true,
            fine_grained_block_coverage: false,
            max_function_blocks: MAX_FUNCTION_BLOCK_COUNT,
            max_function_insns: MAX_FUNCTION_INSN_COUNT,
            max_block_insns: MAX_BLOCK_INSN_COUNT,
            max_candidates_per_invocation: DEFAULT_INVOCATION_CANDIDATE_LIMIT,
            max_functions_per_invocation: DEFAULT_INVOCATION_FUNCTION_LIMIT,
            max_output_bytes_per_invocation: DEFAULT_INVOCATION_OUTPUT_BYTE_LIMIT,
            non_returning_analysis: false,
            segment_function_hints: true,
            segment_mapping_hints: true,
            symbol_table_function_hints: true,
            switch_analysis: false,
        }
    }
}

impl FunctionRecoveryConfig {
    pub fn commit_pending_functions(&self) -> bool {
        self.commit_pending_functions
    }

    pub fn set_commit_pending_functions(&mut self, enabled: bool) {
        self.commit_pending_functions = enabled;
    }

    pub fn with_commit_pending_functions(mut self, enabled: bool) -> Self {
        self.set_commit_pending_functions(enabled);
        self
    }

    pub fn max_function_blocks(&self) -> usize {
        self.max_function_blocks
    }

    pub fn set_max_function_blocks(&mut self, max: usize) {
        self.max_function_blocks = max.clamp(1, MAX_FUNCTION_BLOCK_COUNT);
    }

    pub fn with_max_function_blocks(mut self, max: usize) -> Self {
        self.set_max_function_blocks(max);
        self
    }

    pub fn max_function_insns(&self) -> usize {
        self.max_function_insns
    }

    pub fn set_max_function_insns(&mut self, max: usize) {
        self.max_function_insns = max.clamp(1, MAX_FUNCTION_INSN_COUNT);
    }

    pub fn with_max_function_insns(mut self, max: usize) -> Self {
        self.set_max_function_insns(max);
        self
    }

    pub fn max_block_insns(&self) -> usize {
        self.max_block_insns
    }

    pub fn set_max_block_insns(&mut self, max: usize) {
        self.max_block_insns = max.clamp(1, MAX_BLOCK_INSN_COUNT);
    }

    pub fn with_max_block_insns(mut self, max: usize) -> Self {
        self.set_max_block_insns(max);
        self
    }

    pub fn max_candidates_per_invocation(&self) -> usize {
        self.max_candidates_per_invocation
    }

    pub fn set_max_candidates_per_invocation(&mut self, limit: usize) {
        self.max_candidates_per_invocation = limit.max(1);
    }

    pub fn with_max_candidates_per_invocation(mut self, limit: usize) -> Self {
        self.set_max_candidates_per_invocation(limit);
        self
    }

    pub fn max_functions_per_invocation(&self) -> usize {
        self.max_functions_per_invocation
    }

    pub fn set_max_functions_per_invocation(&mut self, limit: usize) {
        self.max_functions_per_invocation = limit.max(1);
    }

    pub fn with_max_functions_per_invocation(mut self, limit: usize) -> Self {
        self.set_max_functions_per_invocation(limit);
        self
    }

    pub fn max_output_bytes_per_invocation(&self) -> usize {
        self.max_output_bytes_per_invocation
    }

    pub fn set_max_output_bytes_per_invocation(&mut self, limit: usize) {
        self.max_output_bytes_per_invocation = limit.max(1);
    }

    pub fn with_max_output_bytes_per_invocation(mut self, limit: usize) -> Self {
        self.set_max_output_bytes_per_invocation(limit);
        self
    }

    pub fn fine_grained_block_coverage(&self) -> bool {
        self.fine_grained_block_coverage
    }

    pub fn set_fine_grained_block_coverage(&mut self, enabled: bool) {
        self.fine_grained_block_coverage = enabled;
    }

    pub fn with_fine_grained_block_coverage(mut self, enabled: bool) -> Self {
        self.set_fine_grained_block_coverage(enabled);
        self
    }

    pub fn segment_function_hints(&self) -> bool {
        self.segment_function_hints
    }

    pub fn set_segment_function_hints(&mut self, enabled: bool) {
        self.segment_function_hints = enabled;
    }

    pub fn with_segment_function_hints(mut self, enabled: bool) -> Self {
        self.set_segment_function_hints(enabled);
        self
    }

    pub fn segment_mapping_hints(&self) -> bool {
        self.segment_mapping_hints
    }

    pub fn set_segment_mapping_hints(&mut self, enabled: bool) {
        self.segment_mapping_hints = enabled;
    }

    pub fn with_segment_mapping_hints(mut self, enabled: bool) -> Self {
        self.set_segment_mapping_hints(enabled);
        self
    }

    pub fn non_returning_analysis(&self) -> bool {
        self.non_returning_analysis
    }

    pub fn set_non_returning_analysis(&mut self, enabled: bool) {
        self.non_returning_analysis = enabled;
    }

    pub fn with_non_returning_analysis(mut self, enabled: bool) -> Self {
        self.set_non_returning_analysis(enabled);
        self
    }

    pub fn switch_analysis(&self) -> bool {
        self.switch_analysis
    }

    pub fn set_switch_analysis(&mut self, enabled: bool) {
        self.switch_analysis = enabled;
    }

    pub fn with_switch_analysis(mut self, enabled: bool) -> Self {
        self.set_switch_analysis(enabled);
        self
    }

    pub fn symbol_table_function_hints(&self) -> bool {
        self.symbol_table_function_hints
    }

    pub fn set_symbol_table_function_hints(&mut self, enabled: bool) {
        self.symbol_table_function_hints = enabled;
    }

    pub fn with_symbol_table_function_hints(mut self, enabled: bool) -> Self {
        self.set_symbol_table_function_hints(enabled);
        self
    }
}
