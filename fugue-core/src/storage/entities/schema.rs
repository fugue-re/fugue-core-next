use std::hash::Hash;
use std::mem;

use bytes::{BufMut, Bytes, BytesMut};

use crate::ir::{Address, CodeBlock, Function, Id, Insn, RawAddress};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::BytesOrSlice;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EntityKeyId(u8);

impl EntityKeyId {
    pub(crate) const fn new(index: usize) -> Self {
        assert!(index <= u8::MAX as usize, "index out of range");
        Self(index as u8)
    }

    const fn index(&self) -> usize {
        self.0 as usize
    }
}

impl TryFrom<usize> for EntityKeyId {
    type Error = std::num::TryFromIntError;

    fn try_from(index: usize) -> Result<Self, Self::Error> {
        u8::try_from(index).map(Self)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EntityId(u8);

impl EntityId {
    pub(crate) const fn new(index: usize) -> Self {
        assert!(index <= u8::MAX as usize, "index out of range");
        Self(index as u8)
    }

    const fn index(&self) -> usize {
        self.0 as usize
    }
}

impl TryFrom<usize> for EntityId {
    type Error = std::num::TryFromIntError;

    fn try_from(index: usize) -> Result<Self, Self::Error> {
        u8::try_from(index).map(Self)
    }
}

// Packed entity key ID and entity (value) ID
pub const ENTITY_PREFIX_SIZE: usize = mem::size_of::<EntityKeyId>() + mem::size_of::<EntityId>();

// Entity key identifiers
pub const ENTITY_KEY_PROJECT_ENTITY_ID: EntityKeyId = EntityKeyId::new(0);
pub const ENTITY_KEY_ADDRESS_ENTITY_ID: EntityKeyId = EntityKeyId::new(1);
pub const ENTITY_KEY_FUNCTION_ENTITY_ID: EntityKeyId = EntityKeyId::new(2);
pub const ENTITY_KEY_CODE_BLOCK_ENTITY_ID: EntityKeyId = EntityKeyId::new(3);
pub const ENTITY_KEY_INSN_ENTITY_ID: EntityKeyId = EntityKeyId::new(4);
pub const ENTITY_KEY_META_ADDRESS_ENTITY_ID: EntityKeyId = EntityKeyId::new(5);

// Entity identifiers
pub const ENTITY_ARCHITECTURE_ID: EntityId = EntityId::new(0);
pub const ENTITY_ATTRIBUTES_ID: EntityId = EntityId::new(1);
pub const ENTITY_SYMBOL_TABLE_ID: EntityId = EntityId::new(2);
pub const ENTITY_FUNCTION_TABLE_ID: EntityId = EntityId::new(3);
pub const ENTITY_CODE_BLOCK_TABLE_ID: EntityId = EntityId::new(4);

pub const ENTITY_FUNCTION_ID: EntityId = EntityId::new(5);
pub const ENTITY_CODE_BLOCK_ID: EntityId = EntityId::new(6);
pub const ENTITY_INSN_ID: EntityId = EntityId::new(7);

pub type EntityKeyPrefix = [u8; ENTITY_PREFIX_SIZE];

pub trait EntityKey: Clone + PartialEq + Eq + Hash {
    const ID: EntityKeyId;

    fn decode(buf: &[u8]) -> Option<Self>
    where
        Self: Sized;
    fn encode(&self, buf: &mut BytesMut);
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
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

impl EntityKey for RawAddress {
    const ID: EntityKeyId = ENTITY_KEY_ADDRESS_ENTITY_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        <[u8; mem::size_of::<Self>()]>::try_from(buf)
            .ok()
            .map(|val| RawAddress::from(u64::from_be_bytes(val)))
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64(self.offset())
    }
}

impl EntityKey for Address {
    const ID: EntityKeyId = ENTITY_KEY_META_ADDRESS_ENTITY_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        const PACKED_SIZE: usize = mem::size_of::<RawAddress>() + mem::size_of::<AddressSpaceId>();

        if buf.len() < PACKED_SIZE {
            return None;
        }

        let space = AddressSpaceId::from(buf[0]);
        let address = u64::from_be_bytes(buf[1..PACKED_SIZE].try_into().ok()?);

        Some(Address::new(space, address))
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.space().index() as u8);
        buf.put_u64(self.offset());
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

pub trait Entity:
    rkyv::Archive<
        Archived: rkyv::Deserialize<
            Self,
            rkyv::rancor::Strategy<rkyv::de::Pool, rkyv::rancor::Error>,
        > + for<'a> rkyv::bytecheck::CheckBytes<
            rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
        >,
    > + for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            rkyv::util::AlignedVec,
            rkyv::ser::allocator::ArenaHandle<'a>,
            rkyv::rancor::Error,
        >,
    > + Clone
{
    const ID: EntityId;
}

pub(crate) fn make_prefix<K: EntityKey, V: Entity>() -> EntityKeyPrefix {
    [K::ID.index() as u8, V::ID.index() as u8]
}

pub(crate) fn make_key<K: EntityKey, V: Entity>(k: &K) -> Bytes {
    let mut buf = BytesMut::new();
    buf.extend(make_prefix::<K, V>());
    k.encode(&mut buf);
    buf.freeze()
}

pub(crate) fn extract_key<K: EntityKey, V: Entity>(buf: BytesOrSlice<'_>) -> Option<K> {
    if buf.len() < 2 || buf[0] != K::ID.index() as u8 || buf[1] != V::ID.index() as u8 {
        return None;
    }
    K::decode(&buf[2..])
}
