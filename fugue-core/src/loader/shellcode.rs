use std::borrow::Cow;
use std::fmt;
use std::path::Path;
use std::sync::OnceLock;

use fallible_iterator::FallibleIterator;
use thiserror::Error;

use crate::arch::Arch;
use crate::ir::{RawAddress, SegmentProperties};
use crate::lifter::resolve_language;
use crate::loader::{
    ImageAddress, ImageLayout, ImageSegment, ImageSegmentContents, Loadable, LoadableMetadata,
    LoaderError,
};
use crate::storage::segments::mapping::SegmentMappingProvenance;
use crate::types::{AttributeMap, BytesOrMapping};

pub struct Shellcode<'a> {
    address: RawAddress,
    bytes: BytesOrMapping<'a>,
    arch: Arch,
    layout: ImageLayout,
    metadata: OnceLock<LoadableMetadata>,
    path: Option<String>,
    attributes: AttributeMap,
}

impl fmt::Debug for Shellcode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shellcode")
            .field("address", &self.address)
            .field("attributes", &self.attributes)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum ShellcodeError {
    #[error("mapping {1} bytes at {0} will overflow the default address space")]
    AddressOverflow(RawAddress, usize),
    #[error("buffer to map must not be empty")]
    ZeroSized,
}

impl<'a> Shellcode<'a> {
    pub fn new(
        language: impl AsRef<str>,
        address: impl Into<RawAddress>,
        bytes: impl Into<BytesOrMapping<'a>>,
    ) -> Result<Self, LoaderError> {
        Self::new_with(language, address, bytes, AttributeMap::default())
    }

    pub fn new_with(
        language: impl AsRef<str>,
        address: impl Into<RawAddress>,
        bytes: impl Into<BytesOrMapping<'a>>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        let language = resolve_language(language)?;

        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(LoaderError::format(ShellcodeError::ZeroSized));
        }

        let address = address.into();
        let size = bytes.len();

        let arch = Arch::new(language);

        if !address.range_in_space_bounds(arch.language(), size) {
            return Err(LoaderError::format(ShellcodeError::AddressOverflow(
                address, size,
            )));
        }

        let attributes = attributes.into();
        let layout = ImageLayout::single_bank(size as u64)?;

        Ok(Self {
            address,
            bytes,
            arch,
            layout,
            metadata: OnceLock::new(),
            path: None,
            attributes,
        })
    }

    pub fn from_file(
        language: impl AsRef<str>,
        address: impl Into<RawAddress>,
        path: impl AsRef<Path>,
    ) -> Result<Self, LoaderError> {
        Self::from_file_with(language, address, path, AttributeMap::default())
    }

    pub fn from_file_with(
        language: impl AsRef<str>,
        address: impl Into<RawAddress>,
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError> {
        let path = path.as_ref();
        let bytes = BytesOrMapping::from_file(path)?;

        let mut loaded = Self::new_with(language, address, bytes, attributes)?;
        loaded.path = Some(path.display().to_string());

        Ok(loaded)
    }

    pub fn address(&self) -> RawAddress {
        self.address
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Loadable for Shellcode<'_> {
    fn architecture(&self) -> Arch {
        self.arch.clone()
    }

    fn entry_point(&self) -> Option<ImageAddress> {
        Some(ImageAddress::in_default_space(self.address))
    }

    fn image_segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a {
        Box::new(fallible_iterator::once(
            ImageSegment::backed_in_default_bank(
                Cow::Borrowed("LOAD"),
                ImageAddress::in_default_space(self.address),
                self.bytes.len() as u64,
                SegmentProperties::PERM_ALL,
                SegmentMappingProvenance::Segment,
                self.address,
            ),
        ))
    }

    fn image_layout(&self) -> &ImageLayout {
        &self.layout
    }

    fn image_contents<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a {
        Box::new(fallible_iterator::once(ImageSegmentContents::new(
            0u64,
            self.arch.endian(),
            self.bytes(),
        )))
    }

    fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    fn metadata(&self) -> &LoadableMetadata {
        self.metadata.get_or_init(|| {
            LoadableMetadata::new_with(
                &self.bytes,
                self.path.clone(),
                format!("Fugue v{} Shellcode Loader", env!("CARGO_PKG_VERSION")),
            )
        })
    }
}

#[cfg(test)]
mod test {
    use fallible_iterator::FallibleIterator;

    use crate::attributes;
    use crate::ir::RawAddress;
    use crate::loader::Loadable;
    use crate::loader::shellcode::Shellcode;

    #[test]
    #[ignore = "requires FUGUE_LANGUAGE_DIR"]
    fn test_arm_snippet() -> anyhow::Result<()> {
        let shellcode = Shellcode::new_with(
            "ARM:LE:32",
            0x1000u32,
            &[
                0x07, 0x50, 0xa0, 0xe1, 0x00, 0xb0, 0x95, 0xe5, 0x00, 0x10, 0x94, 0xe5, 0x01, 0x20,
                0xa0, 0xe1, 0x00, 0x20, 0x87, 0xe5,
            ],
            attributes![
                "path" => "/path/to/shellcode.exe",
            ],
        )?;

        let regions = shellcode.image_segments().collect::<Vec<_>>()?;
        assert_eq!(regions.len(), 1);

        let region = &regions[0];
        assert_eq!(region.address().offset(), RawAddress::from(0x1000u32));

        let mut lifter = shellcode.architecture().lifter();
        let mut offset = 0usize;
        let mut output = String::new();

        let address = shellcode.address();
        let bytes = shellcode.bytes();

        while offset < bytes.len() {
            let len = lifter
                .disassemble(address + offset as u64, &bytes[offset..], &mut output)
                .expect("valid");
            offset += len;
            output.push('\n');
        }

        assert_eq!(
            output,
            r#"cpy r5,r7
ldr r11,[r5,#0x0]
ldr r1,[r4,#0x0]
cpy r2,r1
str r2,[r7,#0x0]
"#
        );

        Ok(())
    }
}
