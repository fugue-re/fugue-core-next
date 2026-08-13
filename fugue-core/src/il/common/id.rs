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
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
        )]
        #[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
        #[repr(transparent)]
        pub struct $name(std::num::NonZeroU32);

        impl $name {
            pub fn try_from_index(index: usize) -> Result<Self, $crate::il::common::IlError> {
                let value = index
                    .checked_add(1)
                    .and_then(|value| u32::try_from(value).ok())
                    .and_then(std::num::NonZeroU32::new)
                    .ok_or($crate::il::common::IlError::id_exhausted($kind))?;

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

pub(crate) use il_id;

il_id!(IlBlockArgId, "block argument");
il_id!(IlBlockId, "block");
il_id!(IlOpId, "operation");
il_id!(IlExprId, "expression");
il_id!(IlValueId, "value");

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn option_id_uses_non_zero_niche() {
        assert_eq!(std::mem::size_of::<IlBlockId>(), 4);
        assert_eq!(std::mem::size_of::<Option<IlBlockId>>(), 4);
        assert_eq!(std::mem::size_of::<IlBlockArgId>(), 4);
    }

    #[test]
    fn id_index_round_trips() {
        let id = IlOpId::try_from_index(41).unwrap();

        assert_eq!(id.index(), 41);
        assert_eq!(id.value(), 42);
    }

    #[test]
    fn block_argument_id_index_round_trips() {
        let id = IlBlockArgId::try_from_index(41).unwrap();

        assert_eq!(id.index(), 41);
        assert_eq!(id.value(), 42);
    }
}
