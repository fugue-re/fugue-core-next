use std::num::NonZeroU32;

use bytes::{BufMut, BytesMut};

use crate::il::common::{IlError, IrLevel};
use crate::ir::FunctionId;
use crate::storage::entities::schema::{ENTITY_KEY_IR_ARTEFACT_ID, EntityKey, EntityKeyId};

macro_rules! il_id {
    ($name:ident, $kind:literal) => {
        #[derive(
            Debug,
            Copy,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
        )]
        #[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
        #[repr(transparent)]
        pub struct $name(NonZeroU32);

        impl $name {
            pub fn try_from_index(index: usize) -> Result<Self, IlError> {
                let value = index
                    .checked_add(1)
                    .and_then(|value| u32::try_from(value).ok())
                    .and_then(NonZeroU32::new)
                    .ok_or(IlError::id_exhausted($kind))?;

                Ok(Self(value))
            }

            pub const fn index(&self) -> usize {
                self.0.get() as usize - 1
            }

            pub const fn value(&self) -> u32 {
                self.0.get()
            }
        }
    };
}

il_id!(BlockId, "block");
il_id!(OperationId, "operation");
il_id!(ExpressionId, "expression");
il_id!(ValueId, "value");
il_id!(SourceSpanId, "source span");

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct IrArtefactKey {
    function: FunctionId,
    level: IrLevel,
}

impl IrArtefactKey {
    pub const fn new(function: FunctionId, level: IrLevel) -> Self {
        Self { function, level }
    }

    pub const fn function(&self) -> FunctionId {
        self.function
    }

    pub const fn level(&self) -> IrLevel {
        self.level
    }
}

impl EntityKey for IrArtefactKey {
    const ID: EntityKeyId = ENTITY_KEY_IR_ARTEFACT_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != 9 {
            return None;
        }

        let function = FunctionId::decode(&buf[..8])?;
        let level = match buf[8] {
            0 => IrLevel::PCode,
            1 => IrLevel::Llil,
            2 => IrLevel::LlilSsa,
            3 => IrLevel::MappedMlil,
            4 => IrLevel::Mlil,
            _ => return None,
        };

        Some(Self { function, level })
    }

    fn encode(&self, buf: &mut BytesMut) {
        self.function.encode(buf);
        buf.put_u8(self.level as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_id_uses_non_zero_niche() {
        assert_eq!(std::mem::size_of::<BlockId>(), 4);
        assert_eq!(std::mem::size_of::<Option<BlockId>>(), 4);
    }

    #[test]
    fn id_index_round_trips() {
        let id = OperationId::try_from_index(41).unwrap();

        assert_eq!(id.index(), 41);
        assert_eq!(id.value(), 42);
    }

    #[test]
    fn artefact_key_round_trips() {
        let key = IrArtefactKey::new(FunctionId::default(), IrLevel::LlilSsa);
        let mut bytes = BytesMut::new();

        key.encode(&mut bytes);

        assert_eq!(IrArtefactKey::decode(&bytes), Some(key));
    }
}
