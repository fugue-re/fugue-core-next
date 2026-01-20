extern crate self as fugue_core;

pub mod analysis;
pub mod arch;
pub mod ir;
pub mod il;
pub mod lifter;
pub mod loader;
pub mod platform;
pub mod project;
pub mod storage;
pub mod types;

// Re-export derive macro for provider registration
pub use fugue_core_derive::SegmentStorageProvider;

// Re-export inventory for manual registration if needed
pub use inventory;
