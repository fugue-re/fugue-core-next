use std::hash::Hash;
use std::mem;
use std::ops::Deref;

use bytes::Bytes;
use smallvec::SmallVec;

use crate::ir::symbol::Symbol;
use crate::ir::{Address, CodeBlock, Function, Id, Problem, RawAddress, Switch};
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

    pub fn key_for<K: EntityKey>(self, key: &K) -> Bytes {
        let mut bytes = SmallVec::<[u8; INLINE_ENTITY_KEY_SIZE]>::new();
        bytes.extend(EntityKeyPrefix::new(K::ID, self).0);
        key.encode(&mut bytes);
        if bytes.spilled() {
            Bytes::from(bytes.into_vec())
        } else {
            Bytes::copy_from_slice(&bytes)
        }
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
pub const ENTITY_KEY_PROJECT_ID: EntityKeyId = EntityKeyId::new(0);
pub const ENTITY_KEY_RAW_ADDRESS_ID: EntityKeyId = EntityKeyId::new(1);
pub const ENTITY_KEY_FUNCTION_ID: EntityKeyId = EntityKeyId::new(2);
pub const ENTITY_KEY_CODE_BLOCK_ID: EntityKeyId = EntityKeyId::new(3);
pub const ENTITY_KEY_ADDRESS_ID: EntityKeyId = EntityKeyId::new(5);
pub const ENTITY_KEY_SYMBOL_ID: EntityKeyId = EntityKeyId::new(6);
pub const ENTITY_KEY_CALL_GRAPH_FORWARD_ID: EntityKeyId = EntityKeyId::new(7);
pub const ENTITY_KEY_REFERENCE_FORWARD_ID: EntityKeyId = EntityKeyId::new(8);
pub const ENTITY_KEY_REFERENCE_INVERSE_ID: EntityKeyId = EntityKeyId::new(9);
pub const ENTITY_KEY_SWITCH_ID: EntityKeyId = EntityKeyId::new(10);
pub const ENTITY_KEY_CALL_GRAPH_INVERSE_ID: EntityKeyId = EntityKeyId::new(11);
pub const ENTITY_KEY_PROBLEM_ID: EntityKeyId = EntityKeyId::new(12);
pub const ENTITY_KEY_FREE_ID: EntityKeyId = EntityKeyId::new(13);
pub const ENTITY_KEY_FUNCTION_OWNER_ID: EntityKeyId = EntityKeyId::new(14);
pub const ENTITY_KEY_CODE_BLOCK_START_ID: EntityKeyId = EntityKeyId::new(15);
pub const ENTITY_KEY_CODE_BLOCK_SIZE_BUCKET_ID: EntityKeyId = EntityKeyId::new(16);
pub const ENTITY_KEY_CODE_BLOCK_SIZE_BUCKETS_ID: EntityKeyId = EntityKeyId::new(17);
pub const ENTITY_KEY_SYMBOL_NAME_ID: EntityKeyId = EntityKeyId::new(18);
pub const ENTITY_KEY_SYMBOL_ADDRESS_ID: EntityKeyId = EntityKeyId::new(19);
pub const ENTITY_KEY_SYMBOL_LOADER_ID: EntityKeyId = EntityKeyId::new(20);

// Entity identifiers
pub const ENTITY_ARCHITECTURE_ID: EntityId = EntityId::new(0);
pub const ENTITY_ATTRIBUTES_ID: EntityId = EntityId::new(1);
pub const ENTITY_SYMBOL_TABLE_ID: EntityId = EntityId::new(2);
pub const ENTITY_FUNCTION_TABLE_ID: EntityId = EntityId::new(3);
pub const ENTITY_CODE_BLOCK_TABLE_ID: EntityId = EntityId::new(4);
pub const ENTITY_FUNCTION_ID: EntityId = EntityId::new(5);
pub const ENTITY_CODE_BLOCK_ID: EntityId = EntityId::new(6);
pub const ENTITY_SYMBOL_ID: EntityId = EntityId::new(8);
pub const ENTITY_CALL_GRAPH_EDGE_ID: EntityId = EntityId::new(9);
pub const ENTITY_INDEX_HEADER_ID: EntityId = EntityId::new(11);
pub const ENTITY_PROJECT_REVISION_ID: EntityId = EntityId::new(12);
pub const ENTITY_REFERENCE_RECORD_ID: EntityId = EntityId::new(13);
pub const ENTITY_IL_PCODE_ID: EntityId = EntityId::new(15);
pub const ENTITY_IL_ECODE_ID: EntityId = EntityId::new(16);
pub const ENTITY_IL_ECODE_SSA_ID: EntityId = EntityId::new(17);
pub const ENTITY_SWITCH_ID: EntityId = EntityId::new(18);
pub const ENTITY_SWITCH_TABLE_ID: EntityId = EntityId::new(19);
pub const ENTITY_PLATFORM_ID: EntityId = EntityId::new(20);
pub const ENTITY_PROBLEM_TABLE_ID: EntityId = EntityId::new(21);
pub const ENTITY_PROBLEM_ID: EntityId = EntityId::new(22);
pub const ENTITY_COVERAGE_ID: EntityId = EntityId::new(23);
pub const ENTITY_TABLE_INDEX_STATE_ID: EntityId = EntityId::new(24);
pub const ENTITY_FREE_ID_RECORD_ID: EntityId = EntityId::new(25);
pub const ENTITY_FUNCTION_ENTRY_INDEX_ID: EntityId = EntityId::new(26);
pub const ENTITY_FUNCTION_OWNER_INDEX_ID: EntityId = EntityId::new(27);
pub const ENTITY_CODE_BLOCK_START_INDEX_ID: EntityId = EntityId::new(28);
pub const ENTITY_CODE_BLOCK_SIZE_BUCKET_INDEX_ID: EntityId = EntityId::new(29);
pub const ENTITY_CODE_BLOCK_SIZE_BUCKETS_INDEX_ID: EntityId = EntityId::new(30);
pub const ENTITY_SYMBOL_NAME_INDEX_ID: EntityId = EntityId::new(31);
pub const ENTITY_SYMBOL_ADDRESS_INDEX_ID: EntityId = EntityId::new(32);
pub const ENTITY_SYMBOL_LOADER_INDEX_ID: EntityId = EntityId::new(33);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EntityKeyPrefix([u8; ENTITY_PREFIX_SIZE]);

impl EntityKeyPrefix {
    pub const fn new(key: EntityKeyId, entity: EntityId) -> Self {
        Self([key.0, entity.0])
    }

    pub const fn of<K: EntityKey, E: Entity>() -> Self {
        Self::new(K::ID, E::ID)
    }

    pub fn extract<K: EntityKey, E: Entity>(bytes: BytesOrSlice<'_>) -> Option<K> {
        let (prefix, key) = Self::split(bytes.as_ref())?;
        (prefix == Self::of::<K, E>())
            .then(|| K::decode(key))
            .flatten()
    }

    pub fn join(self, key: &[u8]) -> Bytes {
        let mut bytes = SmallVec::<[u8; INLINE_ENTITY_KEY_SIZE]>::new();
        bytes.extend(self.0);
        bytes.extend(key.iter().copied());
        if bytes.spilled() {
            Bytes::from(bytes.into_vec())
        } else {
            Bytes::copy_from_slice(&bytes)
        }
    }

    pub fn split(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let prefix = Self::try_from(bytes.get(..ENTITY_PREFIX_SIZE)?).ok()?;
        Some((prefix, &bytes[ENTITY_PREFIX_SIZE..]))
    }

    pub const fn key_id(self) -> u8 {
        self.0[0]
    }

    pub const fn entity_id(self) -> u8 {
        self.0[1]
    }
}

impl AsRef<[u8]> for EntityKeyPrefix {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for EntityKeyPrefix {
    type Target = [u8; ENTITY_PREFIX_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for EntityKeyPrefix {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; ENTITY_PREFIX_SIZE]>::try_from(value).map(Self)
    }
}

const INLINE_ENTITY_KEY_SIZE: usize = 32;

pub trait EntityKey: Clone + PartialEq + Eq + Hash {
    const ID: EntityKeyId;

    fn decode(buf: &[u8]) -> Option<Self>
    where
        Self: Sized;
    fn encode(&self, output: &mut impl Extend<u8>);
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[repr(u8)]
pub enum ProjectEntity {
    Architecture = 0b0000_0000,
    Platform = 0b0000_1001,
    Attributes = 0b0000_0001,
    FunctionTable = 0b0000_0010,
    SymbolTable = 0b0000_0011,
    CodeBlockTable = 0b0000_0100,
    CallGraphIndex = 0b0000_0101,
    Revision = 0b0000_0110,
    ReferenceIndex = 0b0000_0111,
    SwitchTable = 0b0000_1000,
    ProblemTable = 0b0000_1010,
    Coverage = 0b0000_1011,
}

impl EntityKey for ProjectEntity {
    const ID: EntityKeyId = ENTITY_KEY_PROJECT_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() == 1 {
            match buf[0] {
                0b0000_0000 => Some(ProjectEntity::Architecture),
                0b0000_1001 => Some(ProjectEntity::Platform),
                0b0000_0001 => Some(ProjectEntity::Attributes),
                0b0000_0010 => Some(ProjectEntity::FunctionTable),
                0b0000_0011 => Some(ProjectEntity::SymbolTable),
                0b0000_0100 => Some(ProjectEntity::CodeBlockTable),
                0b0000_0101 => Some(ProjectEntity::CallGraphIndex),
                0b0000_0110 => Some(ProjectEntity::Revision),
                0b0000_0111 => Some(ProjectEntity::ReferenceIndex),
                0b0000_1000 => Some(ProjectEntity::SwitchTable),
                0b0000_1010 => Some(ProjectEntity::ProblemTable),
                0b0000_1011 => Some(ProjectEntity::Coverage),
                _ => None,
            }
        } else {
            None
        }
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend([*self as u8]);
    }
}

impl EntityKey for RawAddress {
    const ID: EntityKeyId = ENTITY_KEY_RAW_ADDRESS_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        <[u8; mem::size_of::<Self>()]>::try_from(buf)
            .ok()
            .map(|val| RawAddress::from(u64::from_be_bytes(val)))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend(self.offset().to_be_bytes())
    }
}

impl EntityKey for Address {
    const ID: EntityKeyId = ENTITY_KEY_ADDRESS_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        const SPACE_SIZE: usize = mem::size_of::<AddressSpaceId>();

        if buf.len() != Self::ENCODED_SIZE {
            return None;
        }

        let space = AddressSpaceId::from(u16::from_be_bytes(buf[..SPACE_SIZE].try_into().ok()?));
        let address = u64::from_be_bytes(buf[SPACE_SIZE..Self::ENCODED_SIZE].try_into().ok()?);

        Some(Address::new(space, address))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend((self.space().index() as u16).to_be_bytes());
        output.extend(self.offset().to_be_bytes());
    }
}

impl Address {
    pub(crate) const ENCODED_SIZE: usize =
        mem::size_of::<AddressSpaceId>() + mem::size_of::<RawAddress>();
}

impl EntityKey for Id<Function> {
    const ID: EntityKeyId = ENTITY_KEY_FUNCTION_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        Id::<Function>::decode_as_key(buf)
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        Id::<Function>::encode(self, output);
    }
}

impl EntityKey for Id<CodeBlock> {
    const ID: EntityKeyId = ENTITY_KEY_CODE_BLOCK_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        Id::<CodeBlock>::decode_as_key(buf)
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        Id::<CodeBlock>::encode(self, output);
    }
}

impl EntityKey for Id<Symbol> {
    const ID: EntityKeyId = ENTITY_KEY_SYMBOL_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        Id::<Symbol>::decode_as_key(buf)
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        Id::<Symbol>::encode(self, output);
    }
}

impl EntityKey for Id<Switch> {
    const ID: EntityKeyId = ENTITY_KEY_SWITCH_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        Id::<Switch>::decode_as_key(buf)
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        Id::<Switch>::encode(self, output);
    }
}

impl EntityKey for Id<Problem> {
    const ID: EntityKeyId = ENTITY_KEY_PROBLEM_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        Id::<Problem>::decode_as_key(buf)
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        Id::<Problem>::encode(self, output);
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_address_key_roundtrips_wide_space() {
        let address = Address::new(AddressSpaceId::new(300), 0xdead_beefu64);
        let encoded = ENTITY_ARCHITECTURE_ID.key_for(&address);
        let decoded = Address::decode(&encoded[ENTITY_PREFIX_SIZE..]).expect("decodes");
        assert_eq!(decoded, address);
        assert_eq!(decoded.space().index(), 300);
    }

    #[test]
    fn test_project_entity_key_roundtrips() {
        for entity in [
            ProjectEntity::Architecture,
            ProjectEntity::Attributes,
            ProjectEntity::FunctionTable,
            ProjectEntity::SymbolTable,
            ProjectEntity::CodeBlockTable,
            ProjectEntity::CallGraphIndex,
            ProjectEntity::Revision,
        ] {
            let encoded = ENTITY_ARCHITECTURE_ID.key_for(&entity);
            assert_eq!(
                ProjectEntity::decode(&encoded[ENTITY_PREFIX_SIZE..]),
                Some(entity)
            );
        }
    }
}
