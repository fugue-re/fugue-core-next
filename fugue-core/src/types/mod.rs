use std::ops::Deref;

pub(crate) mod any;

pub(crate) mod attributes;
pub(crate) mod bytes;
pub(crate) mod memmap;
pub(crate) mod revision;

pub use attributes::{
    ATTRIBUTE_ADDRESS_SPACE, ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_IMAGE_BASE, ATTRIBUTE_INPUT_PATH,
    ATTRIBUTE_LANGUAGE_VARIANT, ATTRIBUTE_PROJECT_PATH, ArchivedAttributeMap, ArchivedJsonValue,
    Attribute, AttributeMap, serde_json,
};
pub use bytes::BytesOrSlice;
pub use fugue_specs::Confidence;
pub use memmap::{BytesOrMapping, SharedBytesOrMapping};
pub use revision::Revision;

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

pub trait EstimateSize {
    fn estimate_size(&self) -> usize;
}
