use thiserror::Error;

use crate::analysis::control::Cancelled;
use crate::il::common::IlLevel;
use crate::ir::FunctionId;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IlError {
    #[error("build cancelled")]
    Cancelled,
    #[error("ID space exhausted for {kind}")]
    IdExhausted { kind: &'static str },
    #[error("integer overflow while constructing {what}")]
    IntegerOverflow { what: &'static str },
    #[error("missing {level} IR for function {function:?}")]
    MissingArtefact {
        function: FunctionId,
        level: IlLevel,
    },
    #[error("{level} operation is missing {component}")]
    MissingComponent {
        level: IlLevel,
        component: &'static str,
    },
    #[error("IR cannot be materialised after semantic mutations in the same transaction")]
    PublishAfterSemanticMutation,
    #[error("range end {end} exceeds pool length {len}")]
    RangeOutOfBounds { end: u32, len: usize },
    #[error("range start {start} exceeds end {end}")]
    ReversedRange { start: u32, end: u32 },
    #[error("{level} schema mismatch: expected {expected}, found {found}")]
    SchemaMismatch {
        level: IlLevel,
        expected: u16,
        found: u16,
    },
    #[error("stale {level} IR: expected input revision {expected}, found {found}")]
    StaleArtefact {
        level: IlLevel,
        expected: u64,
        found: u64,
    },
    #[error("opcode cannot be lifted into {level}")]
    UnsupportedOpcode { level: IlLevel },
    #[error("{level} operation widths do not match")]
    WidthMismatch { level: IlLevel },
}

impl IlError {
    pub const fn id_exhausted(kind: &'static str) -> Self {
        Self::IdExhausted { kind }
    }

    pub const fn integer_overflow(what: &'static str) -> Self {
        Self::IntegerOverflow { what }
    }

    pub const fn missing_artefact(function: FunctionId, level: IlLevel) -> Self {
        Self::MissingArtefact { function, level }
    }

    pub const fn missing_component(level: IlLevel, component: &'static str) -> Self {
        Self::MissingComponent { level, component }
    }

    pub const fn range_out_of_bounds(end: u32, len: usize) -> Self {
        Self::RangeOutOfBounds { end, len }
    }

    pub const fn reversed_range(start: u32, end: u32) -> Self {
        Self::ReversedRange { start, end }
    }

    pub const fn schema_mismatch(level: IlLevel, expected: u16, found: u16) -> Self {
        Self::SchemaMismatch {
            level,
            expected,
            found,
        }
    }

    pub const fn stale_artefact(level: IlLevel, expected: u64, found: u64) -> Self {
        Self::StaleArtefact {
            level,
            expected,
            found,
        }
    }

    pub const fn unsupported_opcode(level: IlLevel) -> Self {
        Self::UnsupportedOpcode { level }
    }

    pub const fn width_mismatch(level: IlLevel) -> Self {
        Self::WidthMismatch { level }
    }
}

impl From<Cancelled> for IlError {
    fn from(_: Cancelled) -> Self {
        Self::Cancelled
    }
}
