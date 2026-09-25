use std::iter::{empty, from_fn};
use std::ops::Bound;
use std::sync::Arc;

use bytes::Bytes;
use crossbeam_skiplist::SkipMap;
use crossbeam_skiplist::map::Range as SkipMapRange;
use dashmap::DashMap;

use super::schema::ENTITY_PREFIX_SIZE;
use super::{
    EntityBytesAsIterator, EntityBytesIterator, EntityBytesReadTransaction,
    EntityBytesWriteTransaction, EntityKeyBytesIterator, EntityKeyPrefix, EntityStorageError,
    EntityStorageProvider, EntityStorageProviderFromLoadable, EntityStorageWriteTransaction,
};
use crate::loader::Loadable;
use crate::storage::{StoragePersistence, TRANSIENT};
use crate::types::{AttributeMap, BytesOrSlice};

pub struct InMemoryEntityStorage {
    data: DashMap<EntityKeyPrefix, Arc<SkipMap<Bytes, Bytes>>>,
}

impl Default for InMemoryEntityStorage {
    fn default() -> Self {
        Self {
            data: DashMap::new(),
        }
    }
}

impl InMemoryEntityStorage {
    pub fn new() -> Self {
        Self::default()
    }

    fn map_for_prefix(&self, prefix: &EntityKeyPrefix) -> Option<Arc<SkipMap<Bytes, Bytes>>> {
        self.data.get(prefix).map(|map| Arc::clone(map.value()))
    }

    fn map_for_insert(&self, prefix: EntityKeyPrefix) -> Arc<SkipMap<Bytes, Bytes>> {
        self.map_for_prefix(&prefix)
            .unwrap_or_else(|| Arc::clone(self.data.entry(prefix).or_default().value()))
    }
}

impl EntityStorageProviderFromLoadable for InMemoryEntityStorage {
    fn from_loadable(
        _loader: &impl Loadable,
        _attributes: &mut AttributeMap,
    ) -> Result<Self, EntityStorageError> {
        Ok(Self::new())
    }
}

impl EntityStorageProvider for InMemoryEntityStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageError> {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let Some(map) = self.map_for_prefix(&prefix) else {
            return Ok(None);
        };

        if let Some(value) = map.get(key) {
            return Ok(Some(BytesOrSlice::from(Bytes::clone(value.value()))));
        }

        Ok(None)
    }

    fn get_as<F, T>(&self, key: &[u8], mut f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let Some(map) = self.map_for_prefix(&prefix) else {
            return Ok(None);
        };

        if let Some(value) = map.get(key) {
            return f(value.value().as_ref()).map(Some);
        }

        Ok(None)
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let map = self.map_for_insert(prefix);
        map.insert(Bytes::copy_from_slice(key), value.into_bytes());

        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if let Some(map) = self.map_for_prefix(&prefix) {
            map.remove(key);
        }

        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let Some(map) = self.map_for_prefix(&prefix) else {
            return Ok(false);
        };

        Ok(map.contains_key(key))
    }

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix =
            EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        let Some(map) = self.map_for_prefix(&prefix) else {
            return Ok(Box::new(empty()));
        };
        let mut iter = InMemoryEntityIterator::from_map(map, Bound::Unbounded);

        Ok(Box::new(from_fn(move || {
            iter.next_key()
                .map(|key| Ok(BytesOrSlice::from(Bytes::from(prefix.join(key.as_ref())))))
        })))
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix =
            EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        let Some(map) = self.map_for_prefix(&prefix) else {
            return Ok(Box::new(empty()));
        };
        let mut iter = InMemoryEntityIterator::from_map(map, Bound::Unbounded);

        Ok(Box::new(from_fn(move || {
            iter.next_entry().map(|(key, value)| {
                Ok((
                    BytesOrSlice::from(Bytes::from(prefix.join(key.as_ref()))),
                    BytesOrSlice::from(value),
                ))
            })
        })))
    }

    fn iter_range(
        &self,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix =
            EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeyFormat)?;
        let start = match start {
            Bound::Included(key) => Bound::Included(Bytes::copy_from_slice(
                key.strip_prefix(prefix.as_ref())
                    .ok_or(EntityStorageError::InvalidKeyFormat)?,
            )),
            Bound::Excluded(key) => Bound::Excluded(Bytes::copy_from_slice(
                key.strip_prefix(prefix.as_ref())
                    .ok_or(EntityStorageError::InvalidKeyFormat)?,
            )),
            Bound::Unbounded => Bound::Unbounded,
        };

        let Some(map) = self.map_for_prefix(&prefix) else {
            return Ok(Box::new(empty()));
        };
        let mut iter = InMemoryEntityIterator::from_map(map, start);

        Ok(Box::new(from_fn(move || {
            iter.next_entry().map(|(key, value)| {
                Ok((
                    BytesOrSlice::from(Bytes::from(prefix.join(key.as_ref()))),
                    BytesOrSlice::from(value),
                ))
            })
        })))
    }

    fn iter_prefix_as<'a, F, T>(
        &'a self,
        prefix: &[u8],
        mut f: F,
    ) -> Result<EntityBytesAsIterator<'a, T>, EntityStorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<T, EntityStorageError> + 'a,
        T: 'a,
    {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix =
            EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        let Some(map) = self.map_for_prefix(&prefix) else {
            return Ok(Box::new(empty()));
        };
        let mut iter = InMemoryEntityIterator::from_map(map, Bound::Unbounded);

        Ok(Box::new(from_fn(move || {
            let (key, value) = iter.next_entry()?;
            let key = prefix.join(key.as_ref());
            Some(f(key.as_ref(), value.as_ref()))
        })))
    }

    fn read_transaction(&self) -> Result<EntityBytesReadTransaction<'_>, EntityStorageError> {
        Err(EntityStorageError::unsupported_with(
            "transactions are not supported by the in-memory storage provider",
        ))
    }

    fn write_transaction(&self) -> Result<EntityBytesWriteTransaction<'_>, EntityStorageError> {
        Ok(Box::new(InMemoryEntityWriter::new(self)))
    }

    fn persistence(&self) -> StoragePersistence {
        TRANSIENT
    }
}

enum InMemoryEntityWrite {
    Insert(EntityKeyPrefix, Bytes, Bytes),
    Remove(EntityKeyPrefix, Bytes),
}

struct InMemoryEntityWriter<'a> {
    storage: &'a InMemoryEntityStorage,
    writes: Vec<InMemoryEntityWrite>,
}

impl<'a> InMemoryEntityWriter<'a> {
    fn new(storage: &'a InMemoryEntityStorage) -> Self {
        Self {
            storage,
            writes: Vec::new(),
        }
    }

    fn split_key(key: &[u8]) -> Result<(EntityKeyPrefix, Bytes), EntityStorageError> {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;
        Ok((prefix, Bytes::copy_from_slice(key)))
    }
}

impl EntityStorageWriteTransaction for InMemoryEntityWriter<'_> {
    fn insert(&mut self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        let (prefix, key) = Self::split_key(key)?;
        self.writes
            .push(InMemoryEntityWrite::Insert(prefix, key, value.into_bytes()));
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), EntityStorageError> {
        let (prefix, key) = Self::split_key(key)?;
        self.writes.push(InMemoryEntityWrite::Remove(prefix, key));
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), EntityStorageError> {
        for write in self.writes {
            match write {
                InMemoryEntityWrite::Insert(prefix, key, value) => {
                    self.storage.map_for_insert(prefix).insert(key, value);
                }
                InMemoryEntityWrite::Remove(prefix, key) => {
                    if let Some(map) = self.storage.map_for_prefix(&prefix) {
                        map.remove(&key);
                    }
                }
            }
        }
        Ok(())
    }
}

#[ouroboros::self_referencing]
struct InMemoryEntityIterator {
    map: Arc<SkipMap<Bytes, Bytes>>,
    #[covariant]
    #[borrows(map)]
    iter: SkipMapRange<'this, Bytes, (Bound<Bytes>, Bound<Bytes>), Bytes, Bytes>,
}

impl InMemoryEntityIterator {
    fn from_map(map: Arc<SkipMap<Bytes, Bytes>>, start: Bound<Bytes>) -> Self {
        InMemoryEntityIteratorBuilder {
            map,
            iter_builder: move |map| map.range((start, Bound::Unbounded)),
        }
        .build()
    }

    fn next_entry(&mut self) -> Option<(Bytes, Bytes)> {
        self.with_iter_mut(|iter| {
            iter.next()
                .map(|entry| (Bytes::clone(entry.key()), Bytes::clone(entry.value())))
        })
    }

    fn next_key(&mut self) -> Option<Bytes> {
        self.with_iter_mut(|iter| iter.next().map(|entry| Bytes::clone(entry.key())))
    }
}

#[cfg(test)]
mod test {
    use std::ops::Bound;

    use super::*;
    use crate::ir::Address;
    use crate::storage::entities::schema::EntityId;
    use crate::storage::entities::{Entity, EntityStorage};

    #[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct TestEntity {
        value: u64,
    }

    impl TestEntity {
        fn new(value: u64) -> Self {
            Self { value }
        }
    }

    impl Entity for TestEntity {
        const ID: EntityId = EntityId::new(127);
    }

    #[test]
    fn dropped_write_transaction_publishes_nothing() -> Result<(), EntityStorageError> {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let address = Address::from(1u64);
        let mut writer = storage.write_transaction()?;
        writer.insert(&address, &TestEntity::new(1))?;
        drop(writer);

        assert_eq!(storage.get::<_, TestEntity>(&address)?, None);
        Ok(())
    }

    #[test]
    fn iterators_release_shard_guard_before_iteration() -> Result<(), EntityStorageError> {
        let storage = InMemoryEntityStorage {
            data: DashMap::with_shard_amount(2),
        };
        let prefix = EntityKeyPrefix::try_from([1, 1].as_slice())
            .map_err(|_| EntityStorageError::InvalidKeyFormat)?;
        let key = prefix.join(b"initial");
        storage.insert(key.as_ref(), BytesOrSlice::from(b"value".as_slice()))?;

        let guard = storage
            .data
            .get(&prefix)
            .expect("the initial entity prefix exists");
        let colliding_prefix = (0..=u16::MAX)
            .map(u16::to_be_bytes)
            .filter_map(|bytes| EntityKeyPrefix::try_from(bytes.as_slice()).ok())
            .find(|candidate| *candidate != prefix && storage.data.try_entry(*candidate).is_none())
            .expect("another entity prefix shares one of two shards");
        drop(guard);

        let entries = storage.iter_prefix(prefix.as_ref())?;
        let key = colliding_prefix.join(b"prefix");
        storage.insert(key.as_ref(), BytesOrSlice::from(b"value".as_slice()))?;
        assert_eq!(entries.collect::<Result<Vec<_>, _>>()?.len(), 1);

        let keys = storage.iter_prefix_keys(prefix.as_ref())?;
        let key = colliding_prefix.join(b"keys");
        storage.insert(key.as_ref(), BytesOrSlice::from(b"value".as_slice()))?;
        assert_eq!(keys.collect::<Result<Vec<_>, _>>()?.len(), 1);

        let start = prefix.join(b"initial");
        let entries = storage.iter_range(prefix.as_ref(), Bound::Included(start.as_ref()))?;
        let key = colliding_prefix.join(b"range");
        storage.insert(key.as_ref(), BytesOrSlice::from(b"value".as_slice()))?;
        assert_eq!(entries.collect::<Result<Vec<_>, _>>()?.len(), 1);

        let entries =
            storage.iter_prefix_as(prefix.as_ref(), |key, value| Ok((key.len(), value.len())))?;
        let key = colliding_prefix.join(b"mapped");
        storage.insert(key.as_ref(), BytesOrSlice::from(b"value".as_slice()))?;
        assert_eq!(entries.collect::<Result<Vec<_>, _>>()?.len(), 1);
        Ok(())
    }

    #[test]
    fn iter_range_respects_inclusive_and_exclusive_bounds() -> Result<(), EntityStorageError> {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());

        for value in 1..=4 {
            storage.insert(&Address::from(value), &TestEntity::new(value))?;
        }

        let included = storage
            .iter_range::<Address, TestEntity>(Bound::Included(&Address::from(2u64)))?
            .map(|entry| entry.map(|(_, entity)| entity.value))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(included, vec![2, 3, 4]);

        let excluded = storage
            .iter_range::<Address, TestEntity>(Bound::Excluded(&Address::from(2u64)))?
            .map(|entry| entry.map(|(_, entity)| entity.value))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(excluded, vec![3, 4]);
        Ok(())
    }
}
