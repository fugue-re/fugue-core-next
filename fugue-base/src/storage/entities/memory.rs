use std::collections::BTreeMap;
use std::mem;

use bytes::{BufMut, Bytes, BytesMut};
use dashmap::mapref::one::Ref as DashMapRef;
use dashmap::DashMap;
use skiplist::skipmap::{Iter as SkipMapIter, Keys as SkipMapKeys};
use skiplist::SkipMap;

use super::common::ENTITY_PREFIX_SIZE;
use super::{
    BytesOrSlice, EntityBytesBulkInserter, EntityBytesIterator, EntityKeyBytesIterator,
    EntityKeyPrefix, EntityStorageBackend, EntityStorageBackendError, EntityStorageBulkInserter,
};

const BATCH_SIZE: usize = 1000;

pub struct InMemoryEntityStorage {
    data: DashMap<EntityKeyPrefix, SkipMap<Bytes, Bytes>>,
}

impl InMemoryEntityStorage {
    pub fn new() -> Self {
        Self {
            data: DashMap::new(),
        }
    }

    fn extract_key_parts(key: &[u8]) -> Option<(EntityKeyPrefix, &[u8])> {
        if key.len() < 2 {
            return None;
        }
        Some(([key[0], key[1]], &key[2..]))
    }

    fn make_key_from_parts(prefix: EntityKeyPrefix, key: &[u8]) -> Bytes {
        let mut full_key = BytesMut::with_capacity(key.len() + ENTITY_PREFIX_SIZE);
        full_key.put_slice(&prefix);
        full_key.put_slice(key);
        full_key.freeze()
    }
}

impl EntityStorageBackend for InMemoryEntityStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageBackendError> {
        let (prefix, key) =
            Self::extract_key_parts(key).ok_or(EntityStorageBackendError::InvalidKeyFormat)?;

        let Some(map) = self.data.get(&prefix) else {
            return Ok(None);
        };

        if let Some(value) = map.get(key) {
            return Ok(Some(BytesOrSlice::from(value)));
        }

        Ok(None)
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageBackendError> {
        let (prefix, key) =
            Self::extract_key_parts(key).ok_or(EntityStorageBackendError::InvalidKeyFormat)?;

        let mut map = self.data.entry(prefix).or_insert_with(SkipMap::new);
        map.insert(Bytes::copy_from_slice(key), value.into_bytes());

        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageBackendError> {
        let (prefix, key) =
            Self::extract_key_parts(key).ok_or(EntityStorageBackendError::InvalidKeyFormat)?;

        if let Some(mut map) = self.data.get_mut(&prefix) {
            map.remove(key);
        }

        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageBackendError> {
        let (prefix, key) =
            Self::extract_key_parts(key).ok_or(EntityStorageBackendError::InvalidKeyFormat)?;

        let Some(map) = self.data.get(&prefix) else {
            return Ok(false);
        };

        Ok(map.contains_key(key))
    }

    fn iter_prefix_keys(
        &self,
        prefix: &[u8],
    ) -> Result<EntityKeyBytesIterator<'_>, EntityStorageBackendError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageBackendError::InvalidKeySize);
        }

        let prefix = EntityKeyPrefix::try_from(prefix)
            .map_err(|_| EntityStorageBackendError::InvalidKeyFormat)?;

        let map = self
            .data
            .get(&prefix)
            .ok_or(EntityStorageBackendError::InvalidKeyFormat)?;

        Ok(Box::new(InMemoryKeyIterator::new(map, prefix, |iter| {
            iter.keys()
        })))
    }

    fn iter_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<EntityBytesIterator<'_>, EntityStorageBackendError> {
        if prefix.len() != ENTITY_PREFIX_SIZE {
            return Err(EntityStorageBackendError::InvalidKeySize);
        }

        let prefix = EntityKeyPrefix::try_from(prefix)
            .map_err(|_| EntityStorageBackendError::InvalidKeyFormat)?;

        let map = self
            .data
            .get(&prefix)
            .ok_or(EntityStorageBackendError::InvalidKeyFormat)?;

        Ok(Box::new(InMemoryIterator::new(map, prefix, |iter| {
            iter.iter()
        })))
    }

    fn bulk_inserter(&self) -> Result<EntityBytesBulkInserter, EntityStorageBackendError> {
        Ok(Box::new(InMemoryEntityInserter::new(self)))
    }
}

#[ouroboros::self_referencing]
struct InMemoryKeyIterator<'a> {
    entry: DashMapRef<'a, EntityKeyPrefix, SkipMap<Bytes, Bytes>>,
    prefix: EntityKeyPrefix,
    #[covariant]
    #[borrows(entry)]
    iter: SkipMapKeys<'this, Bytes, Bytes>,
}

impl<'a> Iterator for InMemoryKeyIterator<'a> {
    type Item = Result<BytesOrSlice<'a>, EntityStorageBackendError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = *self.borrow_prefix();
        self.with_iter_mut(|iter| {
            iter.next().map(|key| {
                Ok(BytesOrSlice::from(
                    InMemoryEntityStorage::make_key_from_parts(prefix, key.as_ref()),
                ))
            })
        })
    }
}

#[ouroboros::self_referencing]
struct InMemoryIterator<'a> {
    entry: DashMapRef<'a, EntityKeyPrefix, SkipMap<Bytes, Bytes>>,
    prefix: EntityKeyPrefix,
    #[covariant]
    #[borrows(entry)]
    iter: SkipMapIter<'this, Bytes, Bytes>,
}

impl<'a> Iterator for InMemoryIterator<'a> {
    type Item = Result<(BytesOrSlice<'a>, BytesOrSlice<'a>), EntityStorageBackendError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = *self.borrow_prefix();
        self.with_iter_mut(|iter| {
            iter.next().map(|(key, bytes)| {
                Ok((
                    BytesOrSlice::from(InMemoryEntityStorage::make_key_from_parts(
                        prefix,
                        key.as_ref(),
                    )),
                    BytesOrSlice::from(bytes),
                ))
            })
        })
    }
}

struct InMemoryEntityInserter<'a> {
    batches: BTreeMap<EntityKeyPrefix, BTreeMap<BytesOrSlice<'a>, BytesOrSlice<'a>>>,
    inner: &'a InMemoryEntityStorage,
}

impl<'a> InMemoryEntityInserter<'a> {
    pub fn new(inner: &'a InMemoryEntityStorage) -> Self {
        Self {
            batches: BTreeMap::new(),
            inner,
        }
    }
}

impl<'a> EntityStorageBulkInserter<'a> for InMemoryEntityInserter<'a> {
    fn insert(
        &mut self,
        key: BytesOrSlice<'a>,
        value: BytesOrSlice<'a>,
    ) -> Result<(), EntityStorageBackendError> {
        let (prefix, key) = InMemoryEntityStorage::extract_key_parts(key.as_slice())
            .ok_or(EntityStorageBackendError::InvalidKeyFormat)?;

        let entry = self.batches.entry(prefix).or_default();

        if entry.len() >= BATCH_SIZE {
            let mut dentry = self.inner.data.entry(prefix).or_insert_with(SkipMap::new);
            dentry.extend(
                mem::take(entry)
                    .into_iter()
                    .map(|(k, v)| (Bytes::copy_from_slice(&k), v.into_bytes())),
            );

            return Ok(());
        }

        entry.insert(Bytes::copy_from_slice(key).into(), value);

        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<(), EntityStorageBackendError> {
        for (prefix, batch) in self.batches {
            let mut map = self.inner.data.entry(prefix).or_insert_with(SkipMap::new);
            map.extend(
                batch
                    .into_iter()
                    .map(|(key, value)| (key.into_bytes(), value.into_bytes())),
            );
        }
        Ok(())
    }
}
