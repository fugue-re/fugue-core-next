use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::{Deref, Range};
use std::path::Path;
use std::sync::Arc;

use memmap2::{Mmap, MmapMut, MmapOptions};
use object::ReadRef;

pub enum BytesOrMapping<'a> {
    Bytes(Cow<'a, [u8]>),
    Mapping(FileMapping),
    MappingMut(MmapMut),
}

pub struct FileMapping {
    file: File,
    map: Mmap,
}

impl FileMapping {
    fn bytes(&self) -> &[u8] {
        self.map.as_ref()
    }
}

impl<'a> AsRef<[u8]> for BytesOrMapping<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes.as_ref(),
            Self::Mapping(mapping) => mapping.bytes(),
            Self::MappingMut(mapping) => mapping.as_ref(),
        }
    }
}

impl<'a> Deref for BytesOrMapping<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a, T> From<T> for BytesOrMapping<'a>
where
    T: Into<Cow<'a, [u8]>> + 'a,
{
    fn from(value: T) -> Self {
        Self::Bytes(value.into())
    }
}

impl<'a> BytesOrMapping<'a> {
    pub fn from_bytes(bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        BytesOrMapping::Bytes(bytes.into())
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, io::Error> {
        let file = File::open(&path)?;
        let map = unsafe { Mmap::map(&file)? };
        Ok(BytesOrMapping::Mapping(FileMapping { file, map }))
    }

    pub fn from_file_mut(path: impl AsRef<Path>) -> Result<Self, io::Error> {
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        let map = unsafe { MmapOptions::new().map_mut(&file)? };
        Ok(BytesOrMapping::MappingMut(map))
    }

    pub fn as_mut(&mut self) -> Option<&mut [u8]> {
        match self {
            Self::MappingMut(mapping) => Some(&mut mapping[..]),
            Self::Bytes(Cow::Owned(bytes)) => Some(bytes.as_mut_slice()),
            Self::Bytes(Cow::Borrowed(_)) | Self::Mapping(_) => None,
        }
    }

    pub fn into_copy_on_write(self) -> Result<Self, io::Error> {
        match self {
            Self::Mapping(FileMapping { file, .. }) => {
                let map = unsafe { MmapOptions::new().map_copy(&file)? };
                Ok(BytesOrMapping::MappingMut(map))
            }
            Self::Bytes(Cow::Borrowed(bytes)) => {
                Ok(BytesOrMapping::Bytes(Cow::Owned(bytes.to_vec())))
            }
            owned @ (Self::Bytes(Cow::Owned(_)) | Self::MappingMut(_)) => Ok(owned),
        }
    }

    pub fn into_owned(self) -> BytesOrMapping<'static> {
        match self {
            Self::Bytes(bytes) => BytesOrMapping::Bytes(Cow::Owned(bytes.into_owned())),
            Self::Mapping(mapping) => BytesOrMapping::Mapping(mapping),
            Self::MappingMut(mapping) => BytesOrMapping::MappingMut(mapping),
        }
    }

    pub fn into_shared(self) -> SharedBytesOrMapping<'a> {
        SharedBytesOrMapping(Arc::new(self))
    }
}

impl<'a> ReadRef<'a> for &'a BytesOrMapping<'_> {
    fn len(self) -> Result<u64, ()> {
        <&'a [u8] as ReadRef<'a>>::len(<[u8]>::as_ref(self))
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
        <&'a [u8] as ReadRef<'a>>::read_bytes_at(<[u8]>::as_ref(self), offset, size)
    }

    fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
        <&'a [u8] as ReadRef<'a>>::read_bytes_at_until(<[u8]>::as_ref(self), range, delimiter)
    }
}

#[derive(Clone)]
#[repr(transparent)]
pub struct SharedBytesOrMapping<'a>(Arc<BytesOrMapping<'a>>);

impl<'a> AsRef<[u8]> for SharedBytesOrMapping<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> Deref for SharedBytesOrMapping<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<'a, T> From<T> for SharedBytesOrMapping<'a>
where
    T: Into<Cow<'a, [u8]>> + 'a,
{
    fn from(value: T) -> Self {
        BytesOrMapping::Bytes(value.into()).into_shared()
    }
}

impl<'a> From<BytesOrMapping<'a>> for SharedBytesOrMapping<'a> {
    fn from(value: BytesOrMapping<'a>) -> Self {
        value.into_shared()
    }
}
