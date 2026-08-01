pub(crate) mod any;

pub(crate) mod attributes;
pub(crate) mod bytes;
pub(crate) mod common;
pub(crate) mod memmap;

pub use attributes::{
    ATTRIBUTE_ADDRESS_SPACE, ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_FILE_PATH, ATTRIBUTE_IMAGE_BASE,
    ATTRIBUTE_PROJECT_PATH, ArchivedAttributeMap, ArchivedJsonValue, Attribute, AttributeMap,
    serde_json,
};
pub use bytes::BytesOrSlice;
pub use common::{OwnedOrRef, Revision};
pub use fugue_specs::Confidence;
pub use memmap::{BytesOrMapping, SharedBytesOrMapping};
