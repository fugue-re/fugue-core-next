use std::cmp::Ordering;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use bytes::Bytes;
use hex_display::Hex;

#[derive(Debug, Clone)]
pub enum BytesOrSlice<'a> {
    Bytes(Bytes),
    Slice(&'a [u8]),
}

impl Display for BytesOrSlice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Hex(self.as_slice()).fmt(f)
    }
}

impl<'a> From<Bytes> for BytesOrSlice<'a> {
    fn from(bytes: Bytes) -> Self {
        BytesOrSlice::Bytes(bytes)
    }
}

impl<'a> From<&'_ Bytes> for BytesOrSlice<'a> {
    fn from(bytes: &Bytes) -> Self {
        BytesOrSlice::Bytes(bytes.clone())
    }
}

impl<'a> From<&'a [u8]> for BytesOrSlice<'a> {
    fn from(slice: &'a [u8]) -> Self {
        BytesOrSlice::Slice(slice)
    }
}

impl<'a> From<Vec<u8>> for BytesOrSlice<'a> {
    fn from(vec: Vec<u8>) -> Self {
        BytesOrSlice::Bytes(Bytes::from(vec))
    }
}

impl<'a> AsRef<[u8]> for BytesOrSlice<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            BytesOrSlice::Bytes(bytes) => bytes.as_ref(),
            BytesOrSlice::Slice(slice) => slice,
        }
    }
}

impl<'a> Deref for BytesOrSlice<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> PartialEq for BytesOrSlice<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<'a> Eq for BytesOrSlice<'a> {}

impl<'a> PartialOrd for BytesOrSlice<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.as_slice().partial_cmp(other.as_slice())
    }
}

impl<'a> Ord for BytesOrSlice<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl<'a> Hash for BytesOrSlice<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl<'a> BytesOrSlice<'a> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            BytesOrSlice::Bytes(bytes) => bytes.as_ref(),
            BytesOrSlice::Slice(slice) => slice,
        }
    }

    pub fn into_bytes(self) -> Bytes {
        match self {
            BytesOrSlice::Bytes(bytes) => bytes,
            BytesOrSlice::Slice(slice) => Bytes::copy_from_slice(slice),
        }
    }
}
