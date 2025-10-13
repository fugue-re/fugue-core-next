use std::fmt::{Debug, LowerHex, UpperHex};
use std::hash::Hash;

use bincode::{Decode, Encode};
use bytes::{BufMut, BytesMut};

pub mod address;
pub use address::{Address, AddressMap, ToAddress};

pub mod block;
pub use block::{BasicBlock, BasicBlockId, BasicBlockProperties};

pub mod cfg;
pub use cfg::{FlowKind, FlowTarget};

pub use fugue_bytes::Endian;

pub mod function;
pub use function::{Function, FunctionId, FunctionProperties, FunctionTable};

pub mod insn;
pub use insn::{Insn, InsnId, InsnList, InsnProperties, InsnTarget, InsnTargetKind};

pub mod module;
pub use module::{Module, ModuleId};

pub mod location;
pub use location::Location;

pub mod segment;
pub use segment::SegmentProperties;

pub mod symbol;
pub use symbol::{
    ExternFunctionTemplate, ExternSymbols, IndexedSymbolTable, LocalSymbols, Symbol, SymbolEntry,
    SymbolId, SymbolIndex, SymbolMap, SymbolProperties, SymbolTable,
};

pub mod traits;

pub struct Id<T> {
    id: u32,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Default for Id<T> {
    fn default() -> Self {
        Self::INVALID
    }
}

impl<T> Debug for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <u32 as Debug>::fmt(&self.id, f)
    }
}

impl<T> LowerHex for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <u32 as LowerHex>::fmt(&self.id, f)
    }
}

impl<T> UpperHex for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <u32 as UpperHex>::fmt(&self.id, f)
    }
}

impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        Id {
            id: self.id,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> Copy for Id<T> {}

impl<T> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<T> Eq for Id<T> {}

impl<T> PartialOrd for Id<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Id<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl<T> Hash for Id<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<T> Id<T> {
    pub const INVALID: Self = Self::new(u32::MAX);

    pub(crate) const fn new(id: u32) -> Self {
        Id {
            id,
            _marker: std::marker::PhantomData,
        }
    }

    pub(crate) const fn from_index(index: usize) -> Self {
        assert!(index < u32::MAX as usize, "invalid index");
        Id {
            id: index as u32,
            _marker: std::marker::PhantomData,
        }
    }

    pub(crate) const fn index(&self) -> usize {
        assert!(self.id < u32::MAX, "invalid index");
        self.id as usize
    }

    #[inline(always)]
    pub const fn is_valid(&self) -> bool {
        !self.is_invalid()
    }

    #[inline(always)]
    pub const fn is_invalid(&self) -> bool {
        self.id == Self::INVALID.id
    }

    // Use for EntityKey::decode implementations
    #[inline(always)]
    pub(crate) fn decode_as_key(buf: &[u8]) -> Option<Self> {
        if buf.len() == 4 {
            Some(Id {
                id: u32::from_be_bytes(buf.try_into().unwrap()),
                _marker: std::marker::PhantomData,
            })
        } else {
            None
        }
    }

    // Use for EntityKey::encode implementations
    #[inline(always)]
    pub(crate) fn encode_as_key(&self, buf: &mut BytesMut) {
        buf.put_u32(self.id);
    }
}

#[repr(transparent)]
pub struct IdSet<T> {
    set: tinyset::SetU32,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Debug for IdSet<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl<T> Default for IdSet<T> {
    fn default() -> Self {
        IdSet::new()
    }
}

impl<T> Clone for IdSet<T> {
    fn clone(&self) -> Self {
        IdSet {
            set: self.set.clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> PartialEq for IdSet<T> {
    fn eq(&self, other: &Self) -> bool {
        self.set == other.set
    }
}

impl<T> Eq for IdSet<T> {}

impl<T> IdSet<T> {
    pub const fn new() -> Self {
        IdSet {
            set: tinyset::SetU32::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn insert(&mut self, id: Id<T>) -> bool {
        self.set.insert(id.id)
    }

    pub fn contains(&self, id: Id<T>) -> bool {
        self.set.contains(id.id)
    }

    pub fn remove(&mut self, id: Id<T>) -> bool {
        self.set.remove(id.id)
    }

    pub fn iter(&self) -> impl Iterator<Item = Id<T>> + '_ {
        self.set.iter().map(|id| Id {
            id,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

impl<T> Encode for Id<T> {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.id.encode(encoder)?;
        Ok(())
    }
}

impl<T, C> Decode<C> for Id<T> {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let id = u32::decode(decoder)?;
        Ok(Id {
            id,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<T> Encode for IdSet<T> {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        // TODO: figure out a more optimal encoding, since this expands the whole
        // set--defeating the purpose of using SetU32 (at least for storage).
        self.len().encode(encoder)?;
        for id in self.iter() {
            id.encode(encoder)?;
        }
        Ok(())
    }
}

impl<T, C> Decode<C> for IdSet<T> {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let len = usize::decode(decoder)?;
        let mut set = IdSet::<T>::new();
        for _ in 0..len {
            let id = Id::<T>::decode(decoder)?;
            set.insert(id);
        }
        Ok(set)
    }
}
