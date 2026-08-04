//! Derived intermediate-language artefacts.
//!
//! An artefact is identified by an [`IlFormId`](common::IlFormId) such as
//! `fugue.ecode.ssa`: a dialect namespace and a form within it. Forms are registered through
//! the crate's extension mechanism, so an out-of-tree crate adds one without editing core.
//!
//! # An ephemeral external form
//!
//! The base contract is [`IlArtefact`](common::IlArtefact). A form that is generated on demand
//! and cached, but never written to the project, needs nothing else:
//!
//! ```
//! use fugue_core::extension::submit;
//! use fugue_core::il::common::{IlArtefact, IlMetadata};
//! use fugue_core::il::registry::{IlDialectRegistration, IlFormRegistration};
//! use fugue_core::ir::FunctionId;
//! use fugue_core::queries::QueryableIl;
//! use fugue_core::types::EstimateSize;
//!
//! #[derive(Debug)]
//! struct CallSummary {
//!     metadata: IlMetadata,
//!     callees: Vec<FunctionId>,
//! }
//!
//! impl EstimateSize for CallSummary {
//!     fn estimate_size(&self) -> usize {
//!         size_of::<Self>() + self.callees.capacity() * size_of::<FunctionId>()
//!     }
//! }
//!
//! impl IlArtefact for CallSummary {
//!     const FORM_IDENTIFIER: &str = "acme.summary.calls";
//!
//!     fn metadata(&self) -> &IlMetadata {
//!         &self.metadata
//!     }
//! }
//!
//! impl QueryableIl for CallSummary {}
//!
//! submit! { IlDialectRegistration::new("acme.summary") }
//! submit! { IlFormRegistration::of::<CallSummary>() }
//! ```
//!
//! `reader.il::<CallSummary>(function)` now type-checks and participates in the shared
//! byte-bounded cache. Registering an [`IlProducer`](common::IlProducer) with
//! [`IlFormRegistration::root`](registry::IlFormRegistration::root), or an
//! [`IlConverter`](common::IlConverter) with
//! [`IlFormRegistration::derived`](registry::IlFormRegistration::derived), additionally lets
//! the engine generate it — `derived` takes its source form from `T::Input`, so a recipe
//! cannot disagree with the type it converts.
//!
//! # Capabilities
//!
//! Beyond the base contract a form opts into what it supports:
//!
//! - [`ControlFlowIl`](common::ControlFlowIl) — the artefact has an
//!   [`IlGraph`](common::IlGraph), which unlocks dominance and the structural verifier.
//! - [`PersistableIl`](common::PersistableIl) — the artefact has a schema and can be written
//!   to the project as a durable override through `ProjectTransaction::replace_il`. Overrides
//!   are stored in one entity family keyed by `(FunctionId, IlFormId)`, and the recorded
//!   schema is checked on load.

pub mod common;
pub mod ecode;
pub mod pcode;
pub mod registry;

pub(crate) mod storage;
