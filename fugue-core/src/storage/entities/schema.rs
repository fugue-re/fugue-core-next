use std::hash::Hash;
use std::mem;

use bincode::{Decode, Encode};
use bytes::{BufMut, Bytes, BytesMut};

use crate::ir::{Address, CodeBlock, Function, Id, Insn};
use crate::types::BytesOrSlice;

pub type EntityKeyId = u8;
pub type EntityId = u8;

pub const ENTITY_PREFIX_SIZE: usize = 2;

// Entity key identifiers
pub const ENTITY_KEY_PROJECT_ENTITY_ID: EntityKeyId = 0;
pub const ENTITY_KEY_ADDRESS_ENTITY_ID: EntityKeyId = 1;
pub const ENTITY_KEY_FUNCTION_ENTITY_ID: EntityKeyId = 2;
pub const ENTITY_KEY_CODE_BLOCK_ENTITY_ID: EntityKeyId = 3;
pub const ENTITY_KEY_INSN_ENTITY_ID: EntityKeyId = 4;

// Entity identifiers
pub const ENTITY_ARCHITECTURE_ID: EntityId = 0;
pub const ENTITY_ATTRIBUTES_ID: EntityId = 1;
pub const ENTITY_SYMBOL_TABLE_ID: EntityId = 2;
pub const ENTITY_FUNCTION_TABLE_ID: EntityId = 3;
pub const ENTITY_CODE_BLOCK_TABLE_ID: EntityId = 4;

pub const ENTITY_FUNCTION_ID: EntityId = 5;
pub const ENTITY_CODE_BLOCK_ID: EntityId = 6;
pub const ENTITY_INSN_ID: EntityId = 7;

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
    Architecture = 0b0000_0000,
    Attributes = 0b0000_0001,
    FunctionTable = 0b0000_0010,
    SymbolTable = 0b0000_0011,
    CodeBlockTable = 0b0000_0100,
}

impl EntityKey for ProjectEntity {
    const ID: EntityKeyId = ENTITY_KEY_PROJECT_ENTITY_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() == 1 {
            match buf[0] {
                0b0000_0000 => Some(ProjectEntity::Architecture),
                0b0000_0001 => Some(ProjectEntity::Attributes),
                0b0000_0010 => Some(ProjectEntity::SymbolTable),
                0b0000_0011 => Some(ProjectEntity::FunctionTable),
                0b0000_0100 => Some(ProjectEntity::CodeBlockTable),
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
    const ID: EntityKeyId = ENTITY_KEY_ADDRESS_ENTITY_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        <[u8; mem::size_of::<Self>()]>::try_from(buf)
            .ok()
            .map(|val| Address::from(u64::from_be_bytes(val)))
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64(self.offset())
    }
}

impl EntityKey for Id<Function> {
    const ID: EntityKeyId = ENTITY_KEY_FUNCTION_ENTITY_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        Id::<Function>::decode_as_key(buf)
    }

    fn encode(&self, buf: &mut BytesMut) {
        Id::<Function>::encode_as_key(self, buf);
    }
}

impl EntityKey for Id<CodeBlock> {
    const ID: EntityKeyId = ENTITY_KEY_CODE_BLOCK_ENTITY_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        Id::<CodeBlock>::decode_as_key(buf)
    }

    fn encode(&self, buf: &mut BytesMut) {
        Id::<CodeBlock>::encode_as_key(self, buf);
    }
}

impl EntityKey for Id<Insn> {
    const ID: EntityKeyId = ENTITY_KEY_INSN_ENTITY_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        Id::<Insn>::decode_as_key(buf)
    }

    fn encode(&self, buf: &mut BytesMut) {
        Id::<Insn>::encode_as_key(self, buf);
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
