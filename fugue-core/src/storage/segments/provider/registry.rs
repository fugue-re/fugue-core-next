use std::any::TypeId;
use std::path::Path;
use std::sync::OnceLock;

use rustc_hash::FxHashMap;

use crate::ir::MetaAddress;
use crate::types::AttributeMap;

use super::{SegmentStorageError, SegmentStorageProvider};

static REGISTRY: OnceLock<SegmentStorageProviderRegistry> = OnceLock::new();

type FromSegmentRangeFn = fn(
    start: MetaAddress,
    end: MetaAddress,
    attributes: &mut AttributeMap,
) -> Result<Box<dyn SegmentStorageProvider>, SegmentStorageError>;

type FromStorageFn = fn(
    path: &Path,
    attributes: &mut AttributeMap,
) -> Result<Box<dyn SegmentStorageProvider>, SegmentStorageError>;

pub struct SegmentStorageProviderEntry {
    type_id: TypeId,
    stable_tag: &'static str,
    from_segment_range: FromSegmentRangeFn,
    from_storage: Option<FromStorageFn>,
}

impl SegmentStorageProviderEntry {
    pub const fn new<T: 'static>(
        stable_tag: &'static str,
        from_segment_range: FromSegmentRangeFn,
        from_storage: FromStorageFn,
    ) -> Self {
        Self::new_with::<T>(
            stable_tag,
            from_segment_range,
            Some(from_storage),
        )
    }

    pub const fn new_with<T: 'static>(
        stable_tag: &'static str,
        from_segment_range: FromSegmentRangeFn,
        from_storage: Option<FromStorageFn>,
    ) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            stable_tag,
            from_segment_range,
            from_storage,
        }
    }

    pub fn is_persistable(&self) -> bool {
        self.from_storage.is_some()
    }
}

inventory::collect!(SegmentStorageProviderEntry);

pub struct SegmentStorageProviderRegistry {
    by_type_id: FxHashMap<TypeId, &'static SegmentStorageProviderEntry>,
    by_tag: FxHashMap<&'static str, &'static SegmentStorageProviderEntry>,
}

impl SegmentStorageProviderRegistry {
    fn new() -> Self {
        let mut by_type_id = FxHashMap::default();
        let mut by_tag = FxHashMap::default();

        for entry in inventory::iter::<SegmentStorageProviderEntry> {
            by_type_id.insert(entry.type_id, entry);
            by_tag.insert(entry.stable_tag, entry);
        }

        Self { by_type_id, by_tag }
    }

    pub fn get() -> &'static Self {
        REGISTRY.get_or_init(SegmentStorageProviderRegistry::new)
    }

    pub fn get_by_type_id(&self, id: TypeId) -> Option<&SegmentStorageProviderEntry> {
        self.by_type_id.get(&id).copied()
    }

    pub fn get_by_tag(&self, tag: &str) -> Option<&SegmentStorageProviderEntry> {
        self.by_tag.get(tag).copied()
    }

    pub fn from_segment_range(
        &self,
        tag: &str,
        start: MetaAddress,
        end: MetaAddress,
        attributes: &mut AttributeMap,
    ) -> Result<Box<dyn SegmentStorageProvider>, SegmentStorageError> {
        let entry = self.by_tag.get(tag).ok_or_else(|| {
            SegmentStorageError::backing_with(format!("unknown provider tag: {tag}"))
        })?;

        (entry.from_segment_range)(start, end, attributes)
    }

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
                "provider `{tag}` does not support from_storage"
            ))
        })?;

        factory(path, attributes)
    }

    pub fn tags(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.by_tag.keys().copied()
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.by_tag.contains_key(tag)
    }

    pub fn len(&self) -> usize {
        self.by_tag.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}
