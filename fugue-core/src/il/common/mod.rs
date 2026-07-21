pub mod artefact;
pub mod dominance;
pub mod error;
pub mod graph;
pub mod id;
pub mod pool;
pub mod span;
pub(crate) mod verify;

pub use artefact::{IlArtefact, IlHeader, IlLevel, IlSchemaVersion, ParseIlLevelError};
pub use dominance::{IlDominance, IlDominanceFrontier};
pub use error::IlError;
pub use graph::{IlBlock, IlBlockPredecessors, IlBlockProperties, IlGraph};
pub use id::{IlBlockId, IlExprId, IlOpId, IlValueId};
pub use pool::IlIndexRange;
pub(crate) use pool::IlPool;
pub use span::{IlParentSpan, IlSourceSpan};
