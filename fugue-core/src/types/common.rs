use std::ops::{Bound, Deref};

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

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
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
pub struct Revision(u64);

impl Revision {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0
    }

    pub const fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<u64> for Revision {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

pub(crate) fn cursor_bound<T>(after: Option<T>) -> Bound<T> {
    after.map_or(Bound::Unbounded, Bound::Excluded)
}

pub(crate) fn cursor_bound_or_minimum<T>(after: Option<T>, minimum: T) -> Bound<T> {
    after.map_or(Bound::Included(minimum), Bound::Excluded)
}

pub enum OwnedOrRef<'a, T> {
    Owned(T),
    Ref(&'a T),
}

impl<'a, T> AsRef<T> for OwnedOrRef<'a, T> {
    fn as_ref(&self) -> &T {
        match self {
            Self::Owned(t) => t,
            Self::Ref(t) => t,
        }
    }
}

impl<'a, T> Deref for OwnedOrRef<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a, T> From<&'a T> for OwnedOrRef<'a, T> {
    fn from(value: &'a T) -> Self {
        Self::Ref(value)
    }
}

impl<'a, T> From<T> for OwnedOrRef<'a, T> {
    fn from(value: T) -> Self {
        Self::Owned(value)
    }
}
