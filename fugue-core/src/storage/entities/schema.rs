use std::hash::Hash;
use std::mem;
use std::ops::Deref;

use bytes::Bytes;
use smallvec::SmallVec;

use crate::types::BytesOrSlice;

const INLINE_ENTITY_KEY_SIZE: usize = 16;

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

    pub fn key_for<K: EntityKey>(self, key: &K) -> EntityKeyBytes {
        let mut bytes = SmallVec::<[u8; INLINE_ENTITY_KEY_SIZE]>::new();
        bytes.extend(EntityKeyPrefix::new(K::ID, self).0);
        key.encode(&mut bytes);
        EntityKeyBytes(bytes)
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
pub const ENTITY_KEY_FUNCTION_BLOCK_ID: EntityKeyId = EntityKeyId::new(14);
pub const ENTITY_KEY_CODE_BLOCK_START_ID: EntityKeyId = EntityKeyId::new(15);
pub const ENTITY_KEY_CODE_BLOCK_SIZE_BUCKET_ID: EntityKeyId = EntityKeyId::new(16);
pub const ENTITY_KEY_CODE_BLOCK_SIZE_BUCKETS_ID: EntityKeyId = EntityKeyId::new(17);
pub const ENTITY_KEY_SYMBOL_NAME_ID: EntityKeyId = EntityKeyId::new(18);
pub const ENTITY_KEY_SYMBOL_ADDRESS_ID: EntityKeyId = EntityKeyId::new(19);
pub const ENTITY_KEY_SYMBOL_LOADER_ID: EntityKeyId = EntityKeyId::new(20);
pub const ENTITY_KEY_IL_OVERRIDE_ID: EntityKeyId = EntityKeyId::new(21);

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
pub const ENTITY_IL_OVERRIDE_ID: EntityId = EntityId::new(15);
pub const ENTITY_SWITCH_ID: EntityId = EntityId::new(18);
pub const ENTITY_SWITCH_TABLE_ID: EntityId = EntityId::new(19);
pub const ENTITY_PLATFORM_ID: EntityId = EntityId::new(20);
pub const ENTITY_PROBLEM_TABLE_ID: EntityId = EntityId::new(21);
pub const ENTITY_PROBLEM_ID: EntityId = EntityId::new(22);
pub const ENTITY_COVERAGE_ID: EntityId = EntityId::new(23);
pub const ENTITY_TABLE_INDEX_STATE_ID: EntityId = EntityId::new(24);
pub const ENTITY_FREE_ID_RECORD_ID: EntityId = EntityId::new(25);
pub const ENTITY_FUNCTION_ENTRY_INDEX_ID: EntityId = EntityId::new(26);
pub const ENTITY_FUNCTION_BLOCK_INDEX_ID: EntityId = EntityId::new(27);
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

    pub const fn key_id(self) -> u8 {
        self.0[0]
    }

    pub const fn entity_id(self) -> u8 {
        self.0[1]
    }

    pub fn extract<K: EntityKey, E: Entity>(bytes: BytesOrSlice<'_>) -> Option<K> {
        let (prefix, mut key) = Self::split(bytes.as_ref())?;
        if prefix != Self::of::<K, E>() {
            return None;
        }

        let decoded = K::decode(&mut key)?;
        key.is_empty().then_some(decoded)
    }

    pub fn join(self, key: &[u8]) -> EntityKeyBytes {
        let mut bytes = SmallVec::<[u8; INLINE_ENTITY_KEY_SIZE]>::new();
        bytes.extend(self.0);
        bytes.extend(key.iter().copied());
        EntityKeyBytes(bytes)
    }

    pub fn split(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let prefix = Self::try_from(bytes.get(..ENTITY_PREFIX_SIZE)?).ok()?;
        Some((prefix, &bytes[ENTITY_PREFIX_SIZE..]))
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityKeyBytes(SmallVec<[u8; INLINE_ENTITY_KEY_SIZE]>);

impl From<EntityKeyBytes> for Bytes {
    fn from(key: EntityKeyBytes) -> Self {
        if key.0.spilled() {
            Self::from(key.0.into_vec())
        } else {
            Self::copy_from_slice(&key.0)
        }
    }
}

impl From<Bytes> for EntityKeyBytes {
    fn from(bytes: Bytes) -> Self {
        Self(SmallVec::from_slice(&bytes))
    }
}

impl AsRef<[u8]> for EntityKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for EntityKeyBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

pub trait EntityKeyCodec: Sized {
    fn decode(input: &mut &[u8]) -> Option<Self>;
    fn encode(&self, output: &mut impl Extend<u8>);
}

pub trait EntityKey: EntityKeyCodec + Clone + PartialEq + Eq + Hash {
    const ID: EntityKeyId;
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

impl EntityKeyCodec for ProjectEntity {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let (&value, rest) = input.split_first()?;
        *input = rest;
        match value {
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
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend([*self as u8]);
    }
}

impl EntityKey for ProjectEntity {
    const ID: EntityKeyId = ENTITY_KEY_PROJECT_ID;
}

pub trait EntityCodec:
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
}

impl<T> EntityCodec for T where
    T: rkyv::Archive<
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
}

pub trait Entity: EntityCodec {
    const ID: EntityId;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::{Address, CodeBlockId, FunctionId, ProblemId, RawAddress, SwitchId, SymbolId};
    use crate::storage::entities::{EntityStorage, EntityStorageError, InMemoryEntityStorage};
    use crate::storage::segments::space::AddressSpaceId;

    #[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct DomainKeyValue {
        value: u64,
    }

    impl DomainKeyValue {
        fn new(value: u64) -> Self {
            Self { value }
        }
    }

    impl Entity for DomainKeyValue {
        const ID: EntityId = EntityId::new(123);
    }

    #[test]
    fn domain_keys_round_trip() -> Result<(), EntityStorageError> {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let raw_address = RawAddress::from(0x0123_4567_89ab_cdefu64);
        storage.insert(&raw_address, &DomainKeyValue::new(1))?;
        assert_eq!(storage.get(&raw_address)?, Some(DomainKeyValue::new(1)));

        let address = Address::new(AddressSpaceId::new(300), 0x0123_4567_89ab_cdefu64);
        storage.insert(&address, &DomainKeyValue::new(2))?;
        assert_eq!(storage.get(&address)?, Some(DomainKeyValue::new(2)));

        let block = CodeBlockId::with_generation(0x1122_3344, 0x5566_7788);
        storage.insert(&block, &DomainKeyValue::new(3))?;
        assert_eq!(storage.get(&block)?, Some(DomainKeyValue::new(3)));

        let function = FunctionId::with_generation(0x1122_3344, 0x5566_7788);
        storage.insert(&function, &DomainKeyValue::new(4))?;
        assert_eq!(storage.get(&function)?, Some(DomainKeyValue::new(4)));

        let problem = ProblemId::with_generation(0x1122_3344, 0x5566_7788);
        storage.insert(&problem, &DomainKeyValue::new(5))?;
        assert_eq!(storage.get(&problem)?, Some(DomainKeyValue::new(5)));

        let switch = SwitchId::with_generation(0x1122_3344, 0x5566_7788);
        storage.insert(&switch, &DomainKeyValue::new(6))?;
        assert_eq!(storage.get(&switch)?, Some(DomainKeyValue::new(6)));

        let symbol = SymbolId::with_generation(0x1122_3344, 0x5566_7788);
        storage.insert(&symbol, &DomainKeyValue::new(7))?;
        assert_eq!(storage.get(&symbol)?, Some(DomainKeyValue::new(7)));

        Ok(())
    }

    #[test]
    fn domain_entity_key_encoding_is_stable() {
        let raw_address = RawAddress::from(0x0123_4567_89ab_cdefu64);
        assert_eq!(
            DomainKeyValue::ID.key_for(&raw_address).as_ref(),
            &[1, 123, 1, 35, 69, 103, 137, 171, 205, 239]
        );

        let address = Address::new(AddressSpaceId::new(300), 0x0123_4567_89ab_cdefu64);
        assert_eq!(
            DomainKeyValue::ID.key_for(&address).as_ref(),
            &[5, 123, 1, 44, 1, 35, 69, 103, 137, 171, 205, 239]
        );

        let id_bytes = [85, 102, 119, 136, 17, 34, 51, 68];
        let block = CodeBlockId::with_generation(0x1122_3344, 0x5566_7788);
        let function = FunctionId::with_generation(0x1122_3344, 0x5566_7788);
        let problem = ProblemId::with_generation(0x1122_3344, 0x5566_7788);
        let switch = SwitchId::with_generation(0x1122_3344, 0x5566_7788);
        let symbol = SymbolId::with_generation(0x1122_3344, 0x5566_7788);

        for (key, prefix) in [
            (DomainKeyValue::ID.key_for(&block), 3),
            (DomainKeyValue::ID.key_for(&function), 2),
            (DomainKeyValue::ID.key_for(&problem), 12),
            (DomainKeyValue::ID.key_for(&switch), 10),
            (DomainKeyValue::ID.key_for(&symbol), 6),
        ] {
            assert_eq!(&key[..ENTITY_PREFIX_SIZE], &[prefix, 123]);
            assert_eq!(&key[ENTITY_PREFIX_SIZE..], &id_bytes);
        }
    }

    #[test]
    fn an_address_key_round_trips_a_wide_space() {
        let address = Address::new(AddressSpaceId::new(300), 0xdead_beefu64);
        let encoded = ENTITY_ARCHITECTURE_ID.key_for(&address);
        let mut key = &encoded[ENTITY_PREFIX_SIZE..];
        let decoded = Address::decode(&mut key).expect("decodes");
        assert!(key.is_empty());
        assert_eq!(decoded, address);
        assert_eq!(decoded.space().index(), 300);
    }

    #[test]
    fn project_entity_keys_round_trip() {
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
            let (prefix, mut key) =
                EntityKeyPrefix::split(encoded.as_ref()).expect("encoded key has prefix");
            assert_eq!(
                prefix,
                EntityKeyPrefix::new(ProjectEntity::ID, ENTITY_ARCHITECTURE_ID)
            );
            assert_eq!(ProjectEntity::decode(&mut key), Some(entity));
            assert!(key.is_empty());
        }
    }
}
