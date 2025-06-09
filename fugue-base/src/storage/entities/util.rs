use uuid::Uuid;

use crate::types::Address;

use super::namespace::Namespace;
use super::{EntityKey, EntityKeyPrefix, StorageBackendError, KEY_SIZE};

pub(crate) fn make_key(namespace: Option<&Namespace>, entity_type: Uuid, address: Address) -> EntityKey {
    let mut key = [0u8; KEY_SIZE];

    // First 16 bytes: cached blake3(namespace + entity_uuid)
    if let Some(namespace) = namespace {
        // Use cached hash from namespace
        key[0..16].copy_from_slice(&namespace.get_entity_hash(entity_type));
    } else {
        // If no namespace provided, use zeroed hash
        key[0..16].copy_from_slice(entity_type.as_bytes());
    }

    // Next 8 bytes: Address in big-endian order for sorted iteration
    key[16..24].copy_from_slice(&address.offset().to_be_bytes());

    key
}

pub(crate) fn make_type_prefix(namespace: Option<&Namespace>, entity_type: Uuid) -> EntityKeyPrefix {
    if let Some(namespace) = namespace {
        // Use cached hash from namespace
        namespace.get_entity_hash(entity_type)
    } else {
        *entity_type.as_bytes()
    }
}

pub(crate) fn extract_address_from_key(key: &[u8]) -> Result<Address, StorageBackendError> {
    if key.len() < KEY_SIZE {
        return Err(StorageBackendError::InvalidKeySize);
    }

    let addr_bytes =
        <[u8; 8]>::try_from(&key[16..24]).map_err(|_| StorageBackendError::InvalidKeyFormat)?;

    Ok(Address::from(u64::from_be_bytes(addr_bytes)))
}

pub(crate) fn extract_namespace_hash_from_key(key: &[u8]) -> Result<EntityKeyPrefix, StorageBackendError> {
    if key.len() < 16 {
        return Err(StorageBackendError::InvalidKeySize);
    }

    let hash_bytes =
        <[u8; 16]>::try_from(&key[0..16]).map_err(|_| StorageBackendError::InvalidKeyFormat)?;

    Ok(hash_bytes)
}
