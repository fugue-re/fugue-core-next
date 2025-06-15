use std::cmp::Ordering;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use bincode::{Decode, Encode};
use bytes::{BufMut, Bytes, BytesMut};
use hex_display::Hex;

use crate::types::Address;

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
