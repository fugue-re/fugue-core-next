pub mod artefact;
pub mod builder;
pub mod dialect;
pub mod entity;
pub mod error;
pub mod mapping;
pub mod pool;
pub mod transform;
pub mod verify;

pub use artefact::{ArtefactDigest, ArtefactHeader, CommonBody, IrArtefact, RawIrArtefact};
pub use builder::{BuildCancellation, BuildStatus, Finish};
pub use dialect::{DialectId, IrLevel, SchemaVersion};
pub use entity::{BlockId, ExpressionId, IrArtefactKey, OperationId, SourceSpanId, ValueId};
pub use error::IlError;
pub use mapping::{CrossLevelMap, MappingRun, SourceMap, SourceRun};
pub use pool::{Block, PackedRange, Pool, PredecessorIndex};
pub use transform::{Scratch, Transform, TransformContext};
pub use verify::{StructuralVerifier, Verify};
