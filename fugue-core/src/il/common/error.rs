use thiserror::Error;

use crate::il::common::{DialectId, IrLevel};
use crate::ir::FunctionId;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IlError {
    #[error("ID space exhausted for {kind}")]
    IdExhausted { kind: &'static str },
    #[error("range start {start} exceeds end {end}")]
    ReversedRange { start: u32, end: u32 },
    #[error("range end {end} exceeds pool length {len}")]
    RangeOutOfBounds { end: u32, len: usize },
    #[error("integer overflow while constructing {what}")]
    IntegerOverflow { what: &'static str },
    #[error("block {block} has duplicate successor {successor}")]
    DuplicateSuccessor { block: usize, successor: usize },
    #[error("block {block} operation range overlaps at operation {operation}")]
    OverlappingBlockOperations { block: u32, operation: u32 },
    #[error("source runs overlap at destination node {node}")]
    OverlappingSourceRun { node: u32 },
    #[error("mapping runs overlap at destination node {node}")]
    OverlappingMappingRun { node: u32 },
    #[error("schema mismatch for {level:?}: expected {expected}, found {found}")]
    SchemaMismatch {
        level: IrLevel,
        expected: u16,
        found: u16,
    },
    #[error("dialect mismatch: expected {expected:?}, found {found:?}")]
    DialectMismatch {
        expected: DialectId,
        found: DialectId,
    },
    #[error("unexpected IR level: expected {expected:?}, found {found:?}")]
    UnexpectedLevel { expected: IrLevel, found: IrLevel },
    #[error("unexpected function: expected {expected:?}, found {found:?}")]
    UnexpectedFunction {
        expected: FunctionId,
        found: FunctionId,
    },
    #[error("artefact digest mismatch")]
    DigestMismatch,
    #[error("{level:?} artefact parent digest mismatch")]
    ParentDigestMismatch { level: IrLevel },
    #[error("{level:?} artefact is missing parent digest")]
    MissingParentDigest { level: IrLevel },
    #[error("failed to decode IR artefact envelope")]
    ArtefactEnvelopeDecode,
    #[error("failed to encode {level:?} artefact payload")]
    ArtefactEncode { level: IrLevel },
    #[error("failed to decode {level:?} artefact payload")]
    ArtefactDecode { level: IrLevel },
    #[error("missing {level:?} artefact for function {function:?}")]
    MissingArtefact {
        function: FunctionId,
        level: IrLevel,
    },
    #[error("stale {level:?} artefact: expected input revision {expected}, found {found}")]
    StaleArtefact {
        level: IrLevel,
        expected: u64,
        found: u64,
    },
    #[error("build cancelled")]
    Cancelled,
    #[error("{dialect:?} operation has invalid operand count: expected {expected}, found {found}")]
    InvalidOperandCount {
        dialect: DialectId,
        expected: usize,
        found: usize,
    },
    #[error("{dialect:?} operation is missing output")]
    MissingOutput { dialect: DialectId },
    #[error("{dialect:?} operation is missing value")]
    MissingValue { dialect: DialectId },
    #[error("{dialect:?} operation is missing immediate")]
    MissingImmediate { dialect: DialectId },
    #[error("{dialect:?} operation has forbidden output")]
    ForbiddenOutput { dialect: DialectId },
    #[error("{dialect:?} operation is missing Fugue address space")]
    MissingAddressSpace { dialect: DialectId },
    #[error("{dialect:?} operation is missing Fugue address")]
    MissingAddress { dialect: DialectId },
    #[error("{dialect:?} operation widths do not match")]
    WidthMismatch { dialect: DialectId },
    #[error("{dialect:?} value has invalid definition")]
    InvalidValueDefinition { dialect: DialectId },
    #[error("{dialect:?} memory domain is missing")]
    MissingMemoryDomain { dialect: DialectId },
    #[error("{dialect:?} memory domain is duplicated")]
    DuplicateMemoryDomain { dialect: DialectId },
    #[error("{dialect:?} value {value} does not dominate use by operation {user}")]
    NonDominatingUse {
        dialect: DialectId,
        value: u32,
        user: u32,
    },
    #[error(
        "{dialect:?} value {value} does not dominate edge from block {predecessor} to block {successor}"
    )]
    NonDominatingEdgeArgument {
        dialect: DialectId,
        value: u32,
        predecessor: u32,
        successor: u32,
    },
    #[error("{dialect:?} operation {operation} has invalid block placement")]
    InvalidOperationPlacement { dialect: DialectId, operation: u32 },
    #[error(
        "{dialect:?} block {block} argument count mismatch: expected {expected}, found {found}"
    )]
    BlockArgumentCount {
        dialect: DialectId,
        block: u32,
        expected: usize,
        found: usize,
    },
    #[error("MLIL project build scheduling is not implemented")]
    MlilBuildSchedulingUnsupported,
    #[error("IR cannot be published after semantic mutations in the same transaction")]
    PublishAfterSemanticMutation,
    #[error("artefact payload is not implemented for {level:?}")]
    ArtefactLevelUnsupported { level: IrLevel },
    #[error("PCode effect opcode cannot be used as an LLIL expression")]
    PCodeEffectOpcodeAsLlilExpression,
    #[error("LLIL statement opcode cannot be lowered to SSA")]
    LlilStatementOpcodeInSsa,
    #[error("LLIL expression opcode cannot be lowered to SSA")]
    LlilExpressionOpcodeInSsa,
}

impl IlError {
    pub const fn id_exhausted(kind: &'static str) -> Self {
        Self::IdExhausted { kind }
    }

    pub const fn reversed_range(start: u32, end: u32) -> Self {
        Self::ReversedRange { start, end }
    }

    pub const fn range_out_of_bounds(end: u32, len: usize) -> Self {
        Self::RangeOutOfBounds { end, len }
    }

    pub const fn integer_overflow(what: &'static str) -> Self {
        Self::IntegerOverflow { what }
    }

    pub const fn duplicate_successor(block: usize, successor: usize) -> Self {
        Self::DuplicateSuccessor { block, successor }
    }

    pub const fn overlapping_block_operations(block: u32, operation: u32) -> Self {
        Self::OverlappingBlockOperations { block, operation }
    }

    pub const fn overlapping_source_run(node: u32) -> Self {
        Self::OverlappingSourceRun { node }
    }

    pub const fn overlapping_mapping_run(node: u32) -> Self {
        Self::OverlappingMappingRun { node }
    }

    pub const fn schema_mismatch(level: IrLevel, expected: u16, found: u16) -> Self {
        Self::SchemaMismatch {
            level,
            expected,
            found,
        }
    }

    pub const fn dialect_mismatch(expected: DialectId, found: DialectId) -> Self {
        Self::DialectMismatch { expected, found }
    }

    pub const fn unexpected_level(expected: IrLevel, found: IrLevel) -> Self {
        Self::UnexpectedLevel { expected, found }
    }

    pub const fn unexpected_function(expected: FunctionId, found: FunctionId) -> Self {
        Self::UnexpectedFunction { expected, found }
    }

    pub const fn digest_mismatch() -> Self {
        Self::DigestMismatch
    }

    pub const fn parent_digest_mismatch(level: IrLevel) -> Self {
        Self::ParentDigestMismatch { level }
    }

    pub const fn missing_parent_digest(level: IrLevel) -> Self {
        Self::MissingParentDigest { level }
    }

    pub const fn artefact_envelope_decode() -> Self {
        Self::ArtefactEnvelopeDecode
    }

    pub const fn artefact_encode(level: IrLevel) -> Self {
        Self::ArtefactEncode { level }
    }

    pub const fn artefact_decode(level: IrLevel) -> Self {
        Self::ArtefactDecode { level }
    }

    pub const fn missing_artefact(function: FunctionId, level: IrLevel) -> Self {
        Self::MissingArtefact { function, level }
    }

    pub const fn stale_artefact(level: IrLevel, expected: u64, found: u64) -> Self {
        Self::StaleArtefact {
            level,
            expected,
            found,
        }
    }

    pub const fn cancelled() -> Self {
        Self::Cancelled
    }

    pub const fn pcode_invalid_operand_count(expected: usize, found: usize) -> Self {
        Self::InvalidOperandCount {
            dialect: DialectId::PCODE,
            expected,
            found,
        }
    }

    pub const fn pcode_missing_output() -> Self {
        Self::MissingOutput {
            dialect: DialectId::PCODE,
        }
    }

    pub const fn pcode_forbidden_output() -> Self {
        Self::ForbiddenOutput {
            dialect: DialectId::PCODE,
        }
    }

    pub const fn llil_missing_value() -> Self {
        Self::MissingValue {
            dialect: DialectId::LLIL,
        }
    }

    pub const fn llil_missing_immediate() -> Self {
        Self::MissingImmediate {
            dialect: DialectId::LLIL,
        }
    }

    pub const fn llil_invalid_operand_count(expected: usize, found: usize) -> Self {
        Self::InvalidOperandCount {
            dialect: DialectId::LLIL,
            expected,
            found,
        }
    }

    pub const fn llil_missing_address_space() -> Self {
        Self::MissingAddressSpace {
            dialect: DialectId::LLIL,
        }
    }

    pub const fn llil_missing_address() -> Self {
        Self::MissingAddress {
            dialect: DialectId::LLIL,
        }
    }

    pub const fn pcode_missing_address_space() -> Self {
        Self::MissingAddressSpace {
            dialect: DialectId::PCODE,
        }
    }

    pub const fn pcode_missing_address() -> Self {
        Self::MissingAddress {
            dialect: DialectId::PCODE,
        }
    }

    pub const fn pcode_width_mismatch() -> Self {
        Self::WidthMismatch {
            dialect: DialectId::PCODE,
        }
    }

    pub const fn llil_ssa_invalid_value_definition() -> Self {
        Self::InvalidValueDefinition {
            dialect: DialectId::LLIL_SSA,
        }
    }

    pub const fn llil_ssa_width_mismatch() -> Self {
        Self::WidthMismatch {
            dialect: DialectId::LLIL_SSA,
        }
    }

    pub const fn llil_ssa_missing_memory_domain() -> Self {
        Self::MissingMemoryDomain {
            dialect: DialectId::LLIL_SSA,
        }
    }

    pub const fn llil_ssa_duplicate_memory_domain() -> Self {
        Self::DuplicateMemoryDomain {
            dialect: DialectId::LLIL_SSA,
        }
    }

    pub const fn llil_ssa_non_dominating_use(value: u32, user: u32) -> Self {
        Self::NonDominatingUse {
            dialect: DialectId::LLIL_SSA,
            value,
            user,
        }
    }

    pub const fn llil_ssa_non_dominating_edge_argument(
        value: u32,
        predecessor: u32,
        successor: u32,
    ) -> Self {
        Self::NonDominatingEdgeArgument {
            dialect: DialectId::LLIL_SSA,
            value,
            predecessor,
            successor,
        }
    }

    pub const fn llil_ssa_invalid_operation_placement(operation: u32) -> Self {
        Self::InvalidOperationPlacement {
            dialect: DialectId::LLIL_SSA,
            operation,
        }
    }

    pub const fn llil_ssa_block_argument_count(block: u32, expected: usize, found: usize) -> Self {
        Self::BlockArgumentCount {
            dialect: DialectId::LLIL_SSA,
            block,
            expected,
            found,
        }
    }

    pub const fn mlil_build_scheduling_unsupported() -> Self {
        Self::MlilBuildSchedulingUnsupported
    }

    pub const fn publish_after_semantic_mutation() -> Self {
        Self::PublishAfterSemanticMutation
    }

    pub const fn artefact_level_unsupported(level: IrLevel) -> Self {
        Self::ArtefactLevelUnsupported { level }
    }

    pub const fn pcode_effect_opcode_as_llil_expression() -> Self {
        Self::PCodeEffectOpcodeAsLlilExpression
    }

    pub const fn llil_statement_opcode_in_ssa() -> Self {
        Self::LlilStatementOpcodeInSsa
    }

    pub const fn llil_expression_opcode_in_ssa() -> Self {
        Self::LlilExpressionOpcodeInSsa
    }
}
