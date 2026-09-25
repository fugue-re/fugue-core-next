use thiserror::Error;

use crate::il::common::IlFormId;
use crate::ir::FunctionId;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IlError {
    #[error("no dialect is registered for stored form `{form}`")]
    DialectUnavailable { form: String },
    #[error("function mismatch: expected {expected:?}, found {found:?}")]
    FunctionMismatch {
        expected: FunctionId,
        found: FunctionId,
    },
    #[error("graph block count mismatch: expected {expected}, found {found}")]
    GraphBlockCountMismatch { expected: usize, found: usize },
    #[error("ID space exhausted for {kind}")]
    IdExhausted { kind: &'static str },
    #[error("a graph cannot mix blocks with and without source addresses")]
    InconsistentBlockSources,
    #[error("integer overflow while constructing {what}")]
    IntegerOverflow { what: &'static str },
    #[error("constructed {form} artefact is invalid")]
    InvalidArtefact { form: IlFormId },
    #[error("operation {operation} cannot carry transformation facts")]
    InvalidFactSite { operation: u32 },
    #[error("a {form} artefact was produced with the wrong Rust type")]
    MismatchedArtefact { form: IlFormId },
    #[error("a {form} artefact was expected as the transformation source")]
    MismatchedSource { form: IlFormId },
    #[error("missing {form} IR for function {function:?}")]
    MissingArtefact {
        function: FunctionId,
        form: IlFormId,
    },
    #[error("{form} operation is missing {component}")]
    MissingComponent {
        form: IlFormId,
        component: &'static str,
    },
    #[error("index map has no terminal boundary")]
    MissingIndexBoundary,
    #[error("no generation recipe is registered for {form}")]
    MissingRecipe { form: IlFormId },
    #[error("range starting at {start} overlaps the preceding range ending at {previous_end}")]
    OverlappingRanges { start: usize, previous_end: usize },
    #[error("IR cannot be materialised after semantic mutations in the same transaction")]
    PublishAfterSemanticMutation,
    #[error("range end {end} exceeds pool length {len}")]
    RangeOutOfBounds { end: usize, len: usize },
    #[error("range start {start} exceeds end {end}")]
    ReversedRange { start: usize, end: usize },
    #[error("{form} schema mismatch: expected {expected}, found {found}")]
    SchemaMismatch {
        form: IlFormId,
        expected: u16,
        found: u16,
    },
    #[error("stale {form} IR: expected input revision {expected}, found {found}")]
    StaleArtefact {
        form: IlFormId,
        expected: u64,
        found: u64,
    },
    #[error("IL form `{form}` is not registered")]
    UnregisteredForm { form: IlFormId },
    #[error("opcode cannot be lifted into {form}")]
    UnsupportedOpcode { form: IlFormId },
    #[error("{form} operation widths do not match")]
    WidthMismatch { form: IlFormId },
}

impl IlError {
    pub fn dialect_unavailable(form: impl Into<String>) -> Self {
        Self::DialectUnavailable { form: form.into() }
    }

    pub const fn function_mismatch(expected: FunctionId, found: FunctionId) -> Self {
        Self::FunctionMismatch { expected, found }
    }

    pub const fn graph_block_count_mismatch(expected: usize, found: usize) -> Self {
        Self::GraphBlockCountMismatch { expected, found }
    }

    pub const fn id_exhausted(kind: &'static str) -> Self {
        Self::IdExhausted { kind }
    }

    pub const fn inconsistent_block_sources() -> Self {
        Self::InconsistentBlockSources
    }

    pub const fn integer_overflow(what: &'static str) -> Self {
        Self::IntegerOverflow { what }
    }

    pub fn invalid_artefact(form: IlFormId) -> Self {
        Self::InvalidArtefact { form }
    }

    pub const fn invalid_fact_site(operation: u32) -> Self {
        Self::InvalidFactSite { operation }
    }

    pub fn mismatched_artefact(form: IlFormId) -> Self {
        Self::MismatchedArtefact { form }
    }

    pub fn mismatched_source(form: IlFormId) -> Self {
        Self::MismatchedSource { form }
    }

    pub fn missing_artefact(function: FunctionId, form: IlFormId) -> Self {
        Self::MissingArtefact { function, form }
    }

    pub fn missing_component(form: IlFormId, component: &'static str) -> Self {
        Self::MissingComponent { form, component }
    }

    pub const fn missing_index_boundary() -> Self {
        Self::MissingIndexBoundary
    }

    pub fn missing_recipe(form: IlFormId) -> Self {
        Self::MissingRecipe { form }
    }

    pub const fn overlapping_ranges(start: usize, previous_end: usize) -> Self {
        Self::OverlappingRanges {
            start,
            previous_end,
        }
    }

    pub const fn publish_after_semantic_mutation() -> Self {
        Self::PublishAfterSemanticMutation
    }

    pub const fn range_out_of_bounds(end: usize, len: usize) -> Self {
        Self::RangeOutOfBounds { end, len }
    }

    pub const fn reversed_range(start: usize, end: usize) -> Self {
        Self::ReversedRange { start, end }
    }

    pub fn schema_mismatch(form: IlFormId, expected: u16, found: u16) -> Self {
        Self::SchemaMismatch {
            form,
            expected,
            found,
        }
    }

    pub fn stale_artefact(form: IlFormId, expected: u64, found: u64) -> Self {
        Self::StaleArtefact {
            form,
            expected,
            found,
        }
    }

    pub fn unregistered_form(form: IlFormId) -> Self {
        Self::UnregisteredForm { form }
    }

    pub fn unsupported_opcode(form: IlFormId) -> Self {
        Self::UnsupportedOpcode { form }
    }

    pub fn width_mismatch(form: IlFormId) -> Self {
        Self::WidthMismatch { form }
    }
}
