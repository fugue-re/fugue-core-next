use std::any::TypeId;
use std::path::Path;
use std::sync::OnceLock;

use rustc_hash::FxHashMap;

use crate::ir::Address;
use crate::types::AttributeMap;

use super::{SegmentStorageError, SegmentStorageProvider};

// Re-export traits from provider module for derive macro access
pub use super::provider::{
    SegmentStorageProviderFromSegmentRange, SegmentStorageProviderFromStorage,
};

/// Factory function for creating a provider from a segment range.
pub type FromSegmentRangeFn = fn(
    start: Address,
    end: Address,
    attributes: &mut AttributeMap,
) -> Result<Box<dyn SegmentStorageProvider>, SegmentStorageError>;

/// Factory function for creating a provider from storage path.
pub type FromStorageFn = fn(
    path: &Path,
    attributes: &mut AttributeMap,
) -> Result<Box<dyn SegmentStorageProvider>, SegmentStorageError>;

/// Registry entry for a provider type.
pub struct ProviderEntry {
    pub type_id: TypeId,
    pub stable_tag: &'static str,
    pub from_segment_range: Option<FromSegmentRangeFn>,
    pub from_storage: Option<FromStorageFn>,
}

inventory::collect!(ProviderEntry);

/// Global registry of provider types built from inventory.
pub struct ProviderRegistry {
    by_type_id: FxHashMap<TypeId, &'static ProviderEntry>,
    by_tag: FxHashMap<&'static str, &'static ProviderEntry>,
}

impl ProviderRegistry {
    fn new() -> Self {
        let mut by_type_id = FxHashMap::default();
        let mut by_tag = FxHashMap::default();

        for entry in inventory::iter::<ProviderEntry> {
            by_type_id.insert(entry.type_id, entry);
            by_tag.insert(entry.stable_tag, entry);
        }

        Self { by_type_id, by_tag }
    }

    /// Get a provider entry by its TypeId.
    pub fn get_by_type_id(&self, id: TypeId) -> Option<&ProviderEntry> {
        self.by_type_id.get(&id).copied()
    }

    /// Get a provider entry by its stable tag.
    pub fn get_by_tag(&self, tag: &str) -> Option<&ProviderEntry> {
        self.by_tag.get(tag).copied()
    }

    /// Create a provider from a segment range using the specified tag.
    pub fn from_segment_range(
        &self,
        tag: &str,
        start: Address,
        end: Address,
        attributes: &mut AttributeMap,
    ) -> Result<Box<dyn SegmentStorageProvider>, SegmentStorageError> {
        let entry = self.by_tag.get(tag).ok_or_else(|| {
            SegmentStorageError::backing_with(format!("unknown provider tag: {tag}"))
        })?;

        let factory = entry.from_segment_range.ok_or_else(|| {
            SegmentStorageError::backing_with(format!(
                "provider '{tag}' does not support from_segment_range"
            ))
        })?;

        factory(start, end, attributes)
    }

    /// Create a provider from storage using the specified tag.
    pub fn from_storage(
        &self,
        tag: &str,
        path: &Path,
        attributes: &mut AttributeMap,
    ) -> Result<Box<dyn SegmentStorageProvider>, SegmentStorageError> {
        let entry = self.by_tag.get(tag).ok_or_else(|| {
            SegmentStorageError::backing_with(format!("unknown provider tag: {tag}"))
        })?;

        let factory = entry.from_storage.ok_or_else(|| {
            SegmentStorageError::backing_with(format!(
                "provider '{tag}' does not support from_storage"
            ))
        })?;

        factory(path, attributes)
    }

    /// Iterate over all registered provider tags.
    pub fn tags(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.by_tag.keys().copied()
    }

    /// Check if a tag is registered.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.by_tag.contains_key(tag)
    }

    /// Get the number of registered providers.
    pub fn len(&self) -> usize {
        self.by_tag.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}

static REGISTRY: OnceLock<ProviderRegistry> = OnceLock::new();

/// Get the global provider registry.
pub fn registry() -> &'static ProviderRegistry {
    REGISTRY.get_or_init(ProviderRegistry::new)
}
