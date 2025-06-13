use std::collections::BTreeMap;
use std::mem;

use bytes::Bytes;
use dashmap::mapref::one::Ref as DashMapRef;
use dashmap::DashMap;
use skiplist::skipmap::{Iter as SkipMapIter, Keys as SkipMapKeys};
use skiplist::SkipMap;

use super::util::make_key_from_parts;
use super::{
    BytesOrSlice, EntityAddress, EntityBulkInserter, EntityBytesIterator, EntityKey,
    EntityKeyBytesIterator, EntityKeyPrefix, EntityStorageBackend, EntityStorageBackendError,
    EntityStorageBulkInserter, ENTITY_PREFIX_SIZE,
};

const BATCH_SIZE: usize = 1000;

pub struct InMemoryEntityStorage {
    data: DashMap<EntityKeyPrefix, SkipMap<EntityAddress, Bytes>>,
}

impl InMemoryEntityStorage {
    pub fn new() -> Self {
        Self {
            data: DashMap::new(),
        }
    }

    fn prefix_and_address(
        &self,
        key: &[u8],
    ) -> Result<(EntityKeyPrefix, EntityAddress), EntityStorageBackendError> {
        if key.len() < ENTITY_PREFIX_SIZE {
            return Err(EntityStorageBackendError::InvalidKeySize);
        }

        let prefix = EntityKeyPrefix::try_from(&key[..ENTITY_PREFIX_SIZE])
            .map_err(|_| EntityStorageBackendError::InvalidKeyFormat)?;

        let address = EntityAddress::try_from(&key[ENTITY_PREFIX_SIZE..])
            .map_err(|_| EntityStorageBackendError::InvalidKeyFormat)?;

        Ok((prefix, address))
    }
}

impl EntityStorageBackend for InMemoryEntityStorage {
    fn get(&self, key: &[u8]) -> Result<Option<BytesOrSlice<'_>>, EntityStorageBackendError> {
        let (prefix, address) = self.prefix_and_address(key)?;

        let Some(map) = self.data.get(&prefix) else {
            return Ok(None);
        };

        if let Some(value) = map.get(&address) {
            return Ok(Some(BytesOrSlice::from(value)));
        }

        Ok(None)
    }

    fn insert(&self, key: &[u8], value: BytesOrSlice<'_>) -> Result<(), EntityStorageBackendError> {
        let (prefix, address) = self.prefix_and_address(key)?;

        let mut map = self.data.entry(prefix).or_insert_with(SkipMap::new);
        map.insert(address, value.into_bytes());

        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EntityStorageBackendError> {
        let (prefix, address) = self.prefix_and_address(key)?;

        if let Some(mut map) = self.data.get_mut(&prefix) {
            map.remove(&address);
        }

        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, EntityStorageBackendError> {
        let (prefix, address) = self.prefix_and_address(key)?;

        let Some(map) = self.data.get(&prefix) else {
            return Ok(false);
        };

        Ok(map.contains_key(&address))
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

    fn bulk_inserter(&self) -> Result<EntityBulkInserter, EntityStorageBackendError> {
        Ok(Box::new(InMemoryEntityInserter::new(self)))
    }
}

#[ouroboros::self_referencing]
struct InMemoryKeyIterator<'a> {
    entry: DashMapRef<'a, EntityKeyPrefix, SkipMap<EntityAddress, Bytes>>,
    prefix: EntityKeyPrefix,
    #[covariant]
    #[borrows(entry)]
    iter: SkipMapKeys<'this, EntityAddress, Bytes>,
}

impl Iterator for InMemoryKeyIterator<'_> {
    type Item = Result<EntityKey, EntityStorageBackendError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = *self.borrow_prefix();
        self.with_iter_mut(|iter| {
            iter.next()
                .map(|address| Ok(make_key_from_parts(prefix, *address)))
        })
    }
}

#[ouroboros::self_referencing]
struct InMemoryIterator<'a> {
    entry: DashMapRef<'a, EntityKeyPrefix, SkipMap<EntityAddress, Bytes>>,
    prefix: EntityKeyPrefix,
    #[covariant]
    #[borrows(entry)]
    iter: SkipMapIter<'this, EntityAddress, Bytes>,
}

impl<'a> Iterator for InMemoryIterator<'a> {
    type Item = Result<(EntityKey, BytesOrSlice<'a>), EntityStorageBackendError>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = *self.borrow_prefix();
        self.with_iter_mut(|iter| {
            iter.next().map(|(address, bytes)| {
                Ok((
                    make_key_from_parts(prefix, *address),
                    BytesOrSlice::from(bytes),
                ))
            })
        })
    }
}

struct InMemoryEntityInserter<'a> {
    batches: BTreeMap<EntityKeyPrefix, BTreeMap<EntityAddress, BytesOrSlice<'a>>>,
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
        key: &[u8],
        value: BytesOrSlice<'a>,
    ) -> Result<(), EntityStorageBackendError> {
        let (prefix, address) = self.inner.prefix_and_address(key)?;

        let entry = self.batches.entry(prefix).or_default();

        if entry.len() >= BATCH_SIZE {
            let mut dentry = self.inner.data.entry(prefix).or_insert_with(SkipMap::new);
            dentry.extend(
                mem::take(entry)
                    .into_iter()
                    .map(|(k, v)| (k, v.into_bytes())),
            );

            return Ok(());
        }

        entry.insert(address, value);

        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<(), EntityStorageBackendError> {
        for (prefix, batch) in self.batches {
            let mut map = self.inner.data.entry(prefix).or_insert_with(SkipMap::new);
            map.extend(
                batch
                    .into_iter()
                    .map(|(address, value)| (address, value.into_bytes())),
            );
        }
        Ok(())
    }
}
