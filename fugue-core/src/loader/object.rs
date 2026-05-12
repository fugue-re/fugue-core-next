use std::borrow::Cow;
use std::path::Path;

use fallible_iterator::FallibleIterator;
use object::{File, Object as ObjectT, ObjectSegment};

use crate::arch::{self, Arch};
use crate::ir::{Address, SegmentProperties};
use crate::lifter::LanguageVariant;
use crate::loader::{
    Loadable, LoadableFromBytes, LoadableFromFile, LoadableMetadata, LoadableSegment,
    LoadableSegmentBounds, LoaderError,
};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::attributes::{
    ATTRIBUTE_ADDRESS_SPACE, ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_IMAGE_BASE,
};
use crate::types::{AttributeMap, BytesOrMapping};

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
    metadata: LoadableMetadata,
    attributes: AttributeMap,
    base: Address,
}

pub fn object_language<'a>(object: &impl ObjectT<'a>) -> Result<LanguageVariant, LoaderError> {
    use object::Architecture as A;

    let is_64 = object.is_64();
    let is_le = object.is_little_endian();

    // FIXME: if we have no entry, then we need to check for other hints...
    let is_thumb = object.entry() & 1 == 1;

    let language = match object.architecture() {
        A::Arm if is_64 && is_le => arch::aarch64::le::variants::DEFAULT,
        A::Arm if is_64 => arch::aarch64::be::variants::DEFAULT,
        A::Arm if is_le => {
            if is_thumb {
                arch::arm::le::variants::DEFAULT_THUMB
            } else {
                arch::arm::le::variants::DEFAULT
            }
        }
        A::Arm => {
            if is_thumb {
                arch::arm::be::variants::DEFAULT_THUMB
            } else {
                arch::arm::be::variants::DEFAULT
            }
        }
        A::I386 => arch::x86::variants::DEFAULT,
        A::X86_64 => arch::x86_64::variants::DEFAULT,
        _ => return Err(LoaderError::UnsupportedArch),
    };

    Ok(language)
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

        let metadata = LoadableMetadata::new(
            object.borrow_data(),
            format!(
                "Fugue v{} Generic \"Object\" Loader",
                env!("CARGO_PKG_VERSION")
            ),
        );

        let mut attributes = attributes.into();

        let target_space = attributes.get_attr::<AddressSpaceId>(ATTRIBUTE_ADDRESS_SPACE);

        let base = attributes
            .get_attr::<Address>(ATTRIBUTE_IMAGE_BASE)
            .map(|addr| Address::in_space(addr, target_space))
            .unwrap_or_else(|| Address::in_space(0u64, target_space));

        let entry = view.entry();

        if entry != 0 {
            attributes.set_attr(ATTRIBUTE_ENTRY_POINT, Address::new(base.space(), entry));
        }

        Ok(Self {
            object,
            arch,
            metadata,
            attributes,
            base,
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, LoaderError> {
        Self::from_file_with(path, AttributeMap::new())
    }

    pub fn from_file_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        let path = path.as_ref();
        let data = BytesOrMapping::from_file(path)?;

        let mut loaded = Self::new_with(data, attributes)?;
        loaded.metadata.set_path(path.display().to_string());

        Ok(loaded)
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
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized, {
        Self::from_file_with(path, attributes)
    }
}

impl Loadable for Object<'_> {
    fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    fn metadata(&self) -> &LoadableMetadata {
        &self.metadata
    }

    fn architecture(&self) -> Arch {
        self.arch.clone()
    }

    fn segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = LoadableSegment<'a>, Error = LoaderError> + 'a {
        let view = self.object.borrow_view();
        let space = self.base.space();

        // NOTE: we need to apply relocations
        // NOTE: we need to make a mapping of externs

        fallible_iterator::convert(view.segments().filter_map(move |segm| {
            if segm.size() == 0 {
                return None;
            }

            let address = Address::new(space, segm.address());
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
                ..Default::default()
            }))
        }))
    }

    fn segment_bounds(&self) -> LoadableSegmentBounds {
        let space = self.base.space();
        let mut start = None::<Address>;
        let mut end = None::<Address>;

        for segm in self.object.borrow_view().segments() {
            if segm.size() == 0 {
                continue;
            }

            let nstart = Address::new(space, segm.address());
            let nend = nstart + segm.size();

            start = Some(start.map_or(nstart, |start| start.min(nstart)));
            end = Some(end.map_or(nend, |end| end.max(nend)));
        }

        LoadableSegmentBounds::new(start.unwrap_or_default()..end.unwrap_or_default())
    }
}
