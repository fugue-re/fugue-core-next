use std::cmp::Ordering;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use bytes::Bytes;
use hex_display::Hex;
use uuid::Uuid;

use crate::types::Address;

use super::namespace::Namespace;
use super::{
    EntityAddress, EntityKey, EntityKeyPrefix, EntityStorageBackendError, ENTITY_KEY_SIZE,
    ENTITY_PREFIX_SIZE,
};

#[derive(Debug, Clone)]
pub enum BytesOrSlice<'a> {
    Bytes(Bytes),
    Slice(&'a [u8]),
}

impl Display for BytesOrSlice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Hex(self.as_slice()).fmt(f)
    }
}

impl<'a> From<Bytes> for BytesOrSlice<'a> {
    fn from(bytes: Bytes) -> Self {
        BytesOrSlice::Bytes(bytes)
    }
}

impl<'a> From<&'_ Bytes> for BytesOrSlice<'a> {
    fn from(bytes: &Bytes) -> Self {
        BytesOrSlice::Bytes(bytes.clone())
    }
}

impl<'a> From<&'a [u8]> for BytesOrSlice<'a> {
    fn from(slice: &'a [u8]) -> Self {
        BytesOrSlice::Slice(slice)
    }
}

impl<'a> From<Vec<u8>> for BytesOrSlice<'a> {
    fn from(vec: Vec<u8>) -> Self {
        BytesOrSlice::Bytes(Bytes::from(vec))
    }
}

impl<'a> AsRef<[u8]> for BytesOrSlice<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            BytesOrSlice::Bytes(bytes) => bytes.as_ref(),
            BytesOrSlice::Slice(slice) => slice,
        }
    }
}

impl<'a> Deref for BytesOrSlice<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> PartialEq for BytesOrSlice<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<'a> Eq for BytesOrSlice<'a> {}

impl<'a> PartialOrd for BytesOrSlice<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.as_slice().partial_cmp(other.as_slice())
    }
}

impl<'a> Ord for BytesOrSlice<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl<'a> Hash for BytesOrSlice<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl<'a> BytesOrSlice<'a> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            BytesOrSlice::Bytes(bytes) => bytes.as_ref(),
            BytesOrSlice::Slice(slice) => slice,
        }
    }

    pub fn into_bytes(self) -> Bytes {
        match self {
            BytesOrSlice::Bytes(bytes) => bytes,
            BytesOrSlice::Slice(slice) => Bytes::copy_from_slice(slice),
        }
    }
}

pub(crate) fn make_key(
    namespace: Option<&Namespace>,
    entity_type: Uuid,
    address: Address,
) -> EntityKey {
    let mut key = [0u8; ENTITY_KEY_SIZE];

    // First 16 bytes: cached blake3(namespace + entity_uuid)
    if let Some(namespace) = namespace {
        // Use cached hash from namespace
        key[..ENTITY_PREFIX_SIZE].copy_from_slice(&namespace.get_entity_hash(entity_type));
    } else {
        // If no namespace provided, use zeroed hash
        key[..ENTITY_PREFIX_SIZE].copy_from_slice(entity_type.as_bytes());
    }

    // Next 8 bytes: Address in big-endian order for sorted iteration
    key[ENTITY_PREFIX_SIZE..].copy_from_slice(&address.offset().to_be_bytes());

    key
}

pub(crate) fn make_key_from_parts(
    prefix: EntityKeyPrefix,
    address: EntityAddress,
) -> EntityKey {
    let mut key = [0u8; ENTITY_KEY_SIZE];
    key[..ENTITY_PREFIX_SIZE].copy_from_slice(&prefix);
    key[ENTITY_PREFIX_SIZE..].copy_from_slice(&address);
    key
}

pub(crate) fn make_type_prefix(
    namespace: Option<&Namespace>,
    entity_type: Uuid,
) -> EntityKeyPrefix {
    if let Some(namespace) = namespace {
        // Use cached hash from namespace
        namespace.get_entity_hash(entity_type)
    } else {
        *entity_type.as_bytes()
    }
}

pub(crate) fn extract_address_from_key(key: &[u8]) -> Result<Address, EntityStorageBackendError> {
    if key.len() < ENTITY_KEY_SIZE {
        return Err(EntityStorageBackendError::InvalidKeySize);
    }

    let addr_bytes = EntityAddress::try_from(&key[ENTITY_PREFIX_SIZE..])
        .map_err(|_| EntityStorageBackendError::InvalidKeyFormat)?;

    Ok(Address::from(u64::from_be_bytes(addr_bytes)))
}

pub(crate) fn extract_namespace_hash_from_key(
    key: &[u8],
) -> Result<EntityKeyPrefix, EntityStorageBackendError> {
    if key.len() < ENTITY_PREFIX_SIZE {
        return Err(EntityStorageBackendError::InvalidKeySize);
    }

    let hash_bytes = EntityKeyPrefix::try_from(&key[..ENTITY_PREFIX_SIZE])
        .map_err(|_| EntityStorageBackendError::InvalidKeyFormat)?;

    Ok(hash_bytes)
}
