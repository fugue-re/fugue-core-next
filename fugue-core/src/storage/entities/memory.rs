use std::ops::Bound;

use bytes::Bytes;
use dashmap::DashMap;
use dashmap::mapref::one::Ref as DashMapRef;
use skiplist::SkipMap;
use skiplist::skipmap::{Iter as SkipMapIter, Keys as SkipMapKeys};

use super::schema::ENTITY_PREFIX_SIZE;
use super::{
    BufferedEntityWriter, EntityBytesAsIterator, EntityBytesIterator, EntityBytesReadTransaction,
    EntityBytesWriteTransaction, EntityKeyBytesIterator, EntityKeyPrefix, EntityStorageError,
    EntityStorageProvider, EntityStorageProviderFromLoadable,
};
use crate::loader::Loadable;
use crate::storage::{StoragePersistence, TRANSIENT};
use crate::types::{AttributeMap, BytesOrSlice};

pub struct InMemoryEntityStorage {
    data: DashMap<EntityKeyPrefix, SkipMap<Bytes, Bytes>>,
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

        let Some(map) = self.data.get(&prefix) else {
            return Ok(None);
        };

        if let Some(value) = map.get(key) {
            return Ok(Some(BytesOrSlice::from(value)));
        }

        Ok(None)
    }

    fn get_as<F, T>(&self, key: &[u8], mut f: F) -> Result<Option<T>, EntityStorageError>
    where
        F: FnMut(&[u8]) -> Result<T, EntityStorageError>,
    {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let Some(map) = self.data.get(&prefix) else {
            return Ok(None);
        };

        if let Some(value) = map.get(key) {
            return f(value.as_ref()).map(Some);
        }

        Ok(None)
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageError> {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let mut map = self.data.entry(prefix).or_default();
        map.insert(Bytes::copy_from_slice(key), value.into_bytes());

        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageError> {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        if let Some(mut map) = self.data.get_mut(&prefix) {
            map.remove(key);
        }

        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageError> {
        let (prefix, key) =
            EntityKeyPrefix::split(key).ok_or(EntityStorageError::InvalidKeyFormat)?;

        let Some(map) = self.data.get(&prefix) else {
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

        let Some(map) = self.data.get(&prefix) else {
            return Ok(Box::new(std::iter::empty()));
        };

        Ok(Box::new(InMemoryEntityKeyBytesIterator::new(
            map,
            prefix,
            |iter| iter.keys(),
        )))
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<EntityBytesIterator<'_>, EntityStorageError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageError::InvalidKeySize);
        }

        let prefix =
            EntityKeyPrefix::try_from(prefix).map_err(|_| EntityStorageError::InvalidKeyFormat)?;

        let Some(map) = self.data.get(&prefix) else {
            return Ok(Box::new(std::iter::empty()));
        };

        Ok(Box::new(InMemoryEntityBytesIterator::new(
            map,
            prefix,
            |iter| iter.iter(),
        )))
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

        let Some(map) = self.data.get(&prefix) else {
            return Ok(Box::new(std::iter::empty()));
        };

        Ok(Box::new(InMemoryEntityBytesIterator::new(
            map,
            prefix,
            |iter| {
                let start = match &start {
                    Bound::Included(key) => Bound::Included(key),
                    Bound::Excluded(key) => Bound::Excluded(key),
                    Bound::Unbounded => Bound::Unbounded,
                };
                iter.range(start, Bound::Unbounded)
            },
        )))
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

        let Some(map) = self.data.get(&prefix) else {
            return Ok(Box::new(std::iter::empty()));
        };

        Ok(Box::new(
            InMemoryEntityBytesIterator::new(map, prefix, |iter| iter.iter())
                .map(move |res| res.and_then(|(k, e)| f(k.as_ref(), e.as_ref()))),
        ))
    }

    fn read_transaction(&self) -> Result<EntityBytesReadTransaction<'_>, EntityStorageError> {
        Err(EntityStorageError::unsupported_with(
            "transactions are not supported by the in-memory storage provider",
        ))
    }

    fn write_transaction(&self) -> Result<EntityBytesWriteTransaction<'_>, EntityStorageError> {
        Ok(Box::new(BufferedEntityWriter::new(self)))
    }

    fn persistence(&self) -> StoragePersistence {
        TRANSIENT
    }
}

#[ouroboros::self_referencing]
struct InMemoryEntityKeyBytesIterator<'a> {
    entry: DashMapRef<'a, EntityKeyPrefix, SkipMap<Bytes, Bytes>>,
    prefix: EntityKeyPrefix,
    #[covariant]
    #[borrows(entry)]
    iter: SkipMapKeys<'this, Bytes, Bytes>,
}

impl<'a> Iterator for InMemoryEntityKeyBytesIterator<'a> {
    type Item = Result<BytesOrSlice<'a>, EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = *self.borrow_prefix();
        self.with_iter_mut(|iter| {
            iter.next()
                .map(|key| Ok(BytesOrSlice::from(Bytes::from(prefix.join(key.as_ref())))))
        })
    }
}

#[ouroboros::self_referencing]
struct InMemoryEntityBytesIterator<'a> {
    entry: DashMapRef<'a, EntityKeyPrefix, SkipMap<Bytes, Bytes>>,
    prefix: EntityKeyPrefix,
    #[covariant]
    #[borrows(entry)]
    iter: SkipMapIter<'this, Bytes, Bytes>,
}

impl<'a> Iterator for InMemoryEntityBytesIterator<'a> {
    type Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = *self.borrow_prefix();
        self.with_iter_mut(|iter| {
            iter.next().map(|(key, bytes)| {
                Ok((
                    BytesOrSlice::from(Bytes::from(prefix.join(key.as_ref()))),
                    BytesOrSlice::from(bytes),
                ))
            })
        })
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
    fn iter_range_respects_inclusive_and_exclusive_bounds() {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());

        for value in 1..=4 {
            storage
                .insert(&Address::from(value), &TestEntity::new(value))
                .unwrap();
        }

        let included = storage
            .iter_range::<Address, TestEntity>(Bound::Included(&Address::from(2u64)))
            .unwrap()
            .map(|entry| entry.map(|(_, entity)| entity.value))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(included, vec![2, 3, 4]);

        let excluded = storage
            .iter_range::<Address, TestEntity>(Bound::Excluded(&Address::from(2u64)))
            .unwrap()
            .map(|entry| entry.map(|(_, entity)| entity.value))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(excluded, vec![3, 4]);
    }
}
