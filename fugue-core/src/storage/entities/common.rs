use std::hash::Hash;

use bincode::{Decode, Encode};
use bytes::{BufMut, Bytes, BytesMut};

use crate::types::{Address, BytesOrSlice};

pub type EntityKeyId = u8;
pub type EntityId = u8;

pub const ENTITY_PREFIX_SIZE: usize = 2;

pub const ENTITY_LOCAL_SYMBOLS_ID: EntityId = 0;
pub const ENTITY_EXTERN_SYMBOLS_ID: EntityId = 1;
pub const ENTITY_ATTRIBUTES_ID: EntityId = 2;

pub const ENTITY_FUNCTION_ID: EntityId = 3;

pub type EntityKeyPrefix = [u8; ENTITY_PREFIX_SIZE];

pub trait EntityKey: Clone + PartialEq + Eq + Hash {
    const ID: EntityKeyId;

    fn decode(buf: &[u8]) -> Option<Self>
    where
        Self: Sized;
    fn encode(&self, buf: &mut BytesMut);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
#[repr(u8)]
pub enum ProjectEntity {
    LocalSymbols  = 0b0000_0000,
    ExternSymbols = 0b0000_0001,
    Attributes    = 0b0000_0010,
}

impl EntityKey for ProjectEntity {
    const ID: EntityKeyId = 0;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() == 1 {
            match buf[0] {
                0b0000_0000 => Some(ProjectEntity::LocalSymbols),
                0b0000_0001 => Some(ProjectEntity::ExternSymbols),
                0b0000_0010 => Some(ProjectEntity::Attributes),
                _ => None,
            }
        } else {
            None
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(*self as u8);
    }
}

impl EntityKey for Address {
    const ID: EntityKeyId = 1;

    fn decode(buf: &[u8]) -> Option<Self> {
        <[u8; 8]>::try_from(buf)
            .ok()
            .map(|val| Address::from(u64::from_be_bytes(val)))
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64(self.offset())
    }
}

pub trait Entity<Context = ()>: Encode + Decode<Context> + Clone {
    const ID: EntityId;
}

pub(crate) fn make_prefix<K: EntityKey, V: Entity>() -> EntityKeyPrefix {
    [K::ID, V::ID]
}

pub(crate) fn make_key<K: EntityKey, V: Entity>(k: &K) -> Bytes {
    let mut buf = BytesMut::new();
    buf.extend(make_prefix::<K, V>());
    k.encode(&mut buf);
    buf.freeze()
}

pub(crate) fn extract_key<K: EntityKey, V: Entity>(buf: BytesOrSlice<'_>) -> Option<K> {
    if buf.len() < 2 || buf[0] != K::ID || buf[1] != V::ID {
        return None;
    }
    K::decode(&buf[2..])
}
