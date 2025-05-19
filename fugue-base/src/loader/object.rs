use std::borrow::Cow;
use std::path::Path;

use fallible_iterator::FallibleIterator;

use object::{File, Object as ObjectT, ObjectSegment};

use crate::arch::Arch;
use crate::lifter::Language;
use crate::loader::{Loadable, LoadableFromBytes, LoadableFromFile, LoadableSegment, LoaderError};
use crate::memory::SegmentProperties;
use crate::types::{Address, AttributeMap, BytesOrMapping};

#[ouroboros::self_referencing]
struct ObjectInner<'a> {
    data: BytesOrMapping<'a>,
    #[borrows(data)]
    #[covariant]
    view: File<'this, &'this BytesOrMapping<'a>>,
}

pub struct Object<'a> {
    object: ObjectInner<'a>,
    arch: Arch,
    attributes: AttributeMap,
}

pub fn object_language<'a>(object: &impl ObjectT<'a>) -> Result<&'static Language, LoaderError> {
    use object::Architecture as A;

    let is_64 = object.is_64();
    let is_le = object.is_little_endian();

    let triple = match object.architecture() {
        A::Arm if is_64 && is_le => crate::lifter::aarch64::le::LANGUAGE,
        A::Arm if is_64 => crate::lifter::aarch64::be::LANGUAGE,
        A::Arm if is_le => crate::lifter::arm::le::LANGUAGE,
        A::Arm => crate::lifter::arm::be::LANGUAGE,
        A::I386 => crate::lifter::x86::LANGUAGE,
        A::X86_64 => crate::lifter::x86_64::LANGUAGE,
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(triple)
}

impl<'a> Object<'a> {
    pub fn new(data: impl Into<BytesOrMapping<'a>>) -> Result<Self, LoaderError> {
        Self::new_with(data, AttributeMap::new())
    }

    pub fn new_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        let object = ObjectInner::try_new(data.into(), |data| {
            File::parse(data).map_err(LoaderError::format)
        })?;

        let view = object.borrow_view();
        let language = object_language(view)?;
        let arch = Arch::new(language);

        Ok(Self {
            object,
            arch,
            attributes: attributes.into(),
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, LoaderError> {
        Self::from_file_with(path, AttributeMap::new())
    }

    pub fn from_file_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        let data = BytesOrMapping::from_file(path)?;
        Self::new_with(data, attributes)
    }
}

impl<'a> LoadableFromBytes<'a> for Object<'a> {
    fn from_bytes_with(
        data: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        Self::new_with(data, attributes)
    }
}

impl LoadableFromFile for Object<'_> {
    fn from_file_with(
        path: impl AsRef<std::path::Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized,
    {
        Self::from_file_with(path, attributes)
    }
}

impl Loadable for Object<'_> {
    fn entry(&self) -> Option<Address> {
        Some(self.object.borrow_view().entry().into())
    }

    fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    fn architecture(&self) -> Arch {
        self.arch.clone()
    }

    fn segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = LoadableSegment<'a>, Error = LoaderError> + 'a {
        let view = self.object.borrow_view();

        // NOTE: we need to apply relocations
        // NOTE: we need to make a mapping of externs

        fallible_iterator::convert(view.segments().into_iter().filter_map(|segm| {
            if segm.size() == 0 {
                return None;
            }

            let address = Address::from(segm.address());
            let data = segm.data().unwrap_or_default();

            let bytes = if data.len() as u64 != segm.size() {
                // we have some partial or fully uninitialised segment?

                let mut data = data.to_owned();
                data.resize(segm.size() as _, 0);

                Cow::Owned(data)
            } else {
                Cow::Borrowed(data)
            };

            Some(Ok(LoadableSegment {
                name: segm
                    .name()
                    .ok()
                    .flatten()
                    .map_or_else(|| Cow::Borrowed("LOAD"), |name| Cow::Owned(name.to_owned())),
                address,
                properties: SegmentProperties::all(),
                bytes,
            }))
        }))
    }

    fn segment_range(&self) -> (Address, Address) {
        let mut start = None::<Address>;
        let mut end = None::<Address>;

        for segm in self.object.borrow_view().segments() {
            if segm.size() == 0 {
                continue;
            }

            let nstart = Address::from(segm.address());
            let nend = nstart + segm.size() - 1usize;

            start = Some(start.map_or(nstart, |start| start.min(nstart)));
            end = Some(end.map_or(nend, |end| end.max(nend)));
        }

        (start.unwrap_or_default(), end.unwrap_or_default())
    }
}
