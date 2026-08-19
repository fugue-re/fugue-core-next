use std::mem::size_of;

use crate::il::common::{FlagId, RegisterId, il_id};

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u8)]
pub enum MCodeVarKind {
    Flag = 0,
    Register = 1,
    Stack = 2,
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct MCodeVar {
    kind: MCodeVarKind,
    storage: u64,
    index: u32,
}

const _: () = assert!(size_of::<MCodeVar>() == 16);

impl MCodeVar {
    pub const fn flag(flag: FlagId, index: u32) -> Self {
        Self {
            kind: MCodeVarKind::Flag,
            storage: flag.value(),
            index,
        }
    }

    pub const fn register(register: RegisterId, index: u32) -> Self {
        Self {
            kind: MCodeVarKind::Register,
            storage: register.value(),
            index,
        }
    }

    pub const fn stack(offset: i64) -> Self {
        Self {
            kind: MCodeVarKind::Stack,
            storage: offset as u64,
            index: 0,
        }
    }

    pub const fn kind(&self) -> MCodeVarKind {
        self.kind
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn flag_id(&self) -> Option<FlagId> {
        match self.kind {
            MCodeVarKind::Flag => Some(FlagId::new(self.storage)),
            _ => None,
        }
    }

    pub const fn register_id(&self) -> Option<RegisterId> {
        match self.kind {
            MCodeVarKind::Register => Some(RegisterId::new(self.storage)),
            _ => None,
        }
    }

    pub const fn stack_offset(&self) -> Option<i64> {
        match self.kind {
            MCodeVarKind::Stack => Some(self.storage as i64),
            _ => None,
        }
    }

}

il_id!(MCodeVarId, "MCode variable");

const _: () = assert!(size_of::<Option<MCodeVarId>>() == 4);
