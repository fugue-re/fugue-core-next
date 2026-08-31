macro_rules! archived_bitflags {
    ($flags:ty, $archived:ident, $bits:ty) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $archived(rkyv::Archived<$bits>);

        unsafe impl rkyv::Portable for $archived {}
        unsafe impl rkyv::traits::NoUndef for $archived {}

        unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C> for $archived
        where
            rkyv::Archived<$bits>: rkyv::bytecheck::CheckBytes<C>,
        {
            unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
                unsafe {
                    <rkyv::Archived<$bits> as rkyv::bytecheck::CheckBytes<C>>::check_bytes(
                        value.cast(),
                        context,
                    )
                }
            }
        }

        impl rkyv::Archive for $flags {
            type Archived = $archived;
            type Resolver = rkyv::Resolver<$bits>;

            fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
                let out = unsafe { out.cast_unchecked::<rkyv::Archived<$bits>>() };
                rkyv::Archive::resolve(&self.bits(), resolver, out);
            }
        }

        impl<S> rkyv::Serialize<S> for $flags
        where
            S: rkyv::rancor::Fallible + rkyv::ser::Writer<S::Error> + ?Sized,
        {
            fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
                rkyv::Serialize::serialize(&self.bits(), serializer)
            }
        }

        impl<D: rkyv::rancor::Fallible + ?Sized> rkyv::Deserialize<$flags, D> for $archived {
            fn deserialize(&self, deserializer: &mut D) -> Result<$flags, D::Error> {
                let bits = rkyv::Deserialize::<$bits, D>::deserialize(&self.0, deserializer)?;
                Ok(<$flags>::from_bits_truncate(bits))
            }
        }
    };
}

pub(crate) use archived_bitflags;
