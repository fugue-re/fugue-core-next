use std::hash::Hash;

use bincode::{Decode, Encode};
use bytes::{BufMut, Bytes, BytesMut};

use crate::types::{Address, BytesOrSlice};

pub type EntityKeyId = u8;
pub type EntityId = u8;

pub const ENTITY_PREFIX_SIZE: usize = 2;

pub type EntityKeyPrefix = [u8; ENTITY_PREFIX_SIZE];

pub trait EntityKey: Copy + Clone + PartialEq + Eq + Hash {
    const ID: EntityKeyId;

    fn decode(buf: &[u8]) -> Option<Self>
    where
        Self: Sized;
    fn encode(&self, buf: &mut BytesMut);
}

impl EntityKey for Address {
    const ID: EntityKeyId = 0;

    fn decode(buf: &[u8]) -> Option<Self> {
        <[u8; 8]>::try_from(buf)
            .ok()
            .map(|val| Address::from(u64::from_be_bytes(val)))
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64(self.offset())
    }
}

pub trait Entity<Context = ()>: Encode + Decode<Context> + Clone + Send + Sync {
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
