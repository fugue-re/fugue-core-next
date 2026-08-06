mod cache;
mod engine;
mod entities;
mod index;
mod project;
mod reader;
mod term;

pub use cache::QueryableIl;
pub(crate) use engine::{IlLookup, QueryEngine};
pub use entities::{CallEdge, MappingEntity, ProblemEntity, QueryPage, SwitchEntity, SymbolEntity};
pub(crate) use reader::MAX_QUERY_PAGE_SIZE;
pub use reader::{ProjectHandle, QueryError, QueryReader};
pub use term::{Dependency, Term};
