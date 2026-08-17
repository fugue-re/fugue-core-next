mod analysis;
mod artefact;
mod constants;
mod dominance;
mod error;
mod evaluate;
mod form;
mod generate;
mod graph;
mod id;
mod pool;
mod register;
mod rewrite;
mod span;
mod ssa;
pub(crate) mod verify;

pub use analysis::{IlAnalyser, IlAnalysis};
pub use artefact::{ControlFlowIl, IlArtefact, IlMetadata, IlSchemaVersion, PersistableIl};
pub(crate) use constants::IlConstantInterner;
pub use dominance::{
    IlDominance, IlDominanceEvent, IlDominanceEvents, IlDominanceFrontier, IlPhiPlacement,
};
pub use error::IlError;
pub(crate) use evaluate::IlScalarOp;
pub use form::{DialectId, IlFormId, IlFormIdError};
pub use generate::{IlGenerationContext, IlGenerationError, IlProducer, IlSubject, IlTransformer};
pub use graph::{
    IlBlock, IlBlockPredecessors, IlBlockProperties, IlEdgeKinds, IlGraph, IlGraphBuilder,
};
pub use id::{IlBlockArgId, IlBlockId, IlExprId, IlOpId, IlValueId, il_id};
pub use pool::{IlCsr, IlIndexMapper, IlIndexRange, IlIndexRangeMap, IlPool};
pub use register::{FlagId, RegisterBank, RegisterId, RegisterRange, RegisterSlice};
pub use rewrite::IlRewrite;
pub use span::{IlParentSpan, IlSourceSpan};
pub use ssa::{IlRequiredDefs, IlSsaDef, SsaIl};
pub(crate) use ssa::{IlSsaBlockArgInputs, collect_ssa_uses};
pub use verify::{SsaVerifier, SsaVerifyError, StructureError, StructureVerifierError};
