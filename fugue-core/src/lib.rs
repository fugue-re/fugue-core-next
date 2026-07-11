extern crate self as fugue_core;

pub mod analysis;
pub mod arch;
pub mod engine;
pub mod il;
pub mod ir;
pub mod lifter;
pub mod loader;
pub mod platform;
pub mod project;
pub mod queries;
pub mod registry;
pub mod storage;
pub mod types;

// Re-export derive macro for provider registration
pub use fugue_core_derive::{SegmentStorageProvider, extension};
