use std::borrow::Cow;
use std::fmt;
use std::path::Path;
use std::sync::OnceLock;

use fallible_iterator::FallibleIterator;
use thiserror::Error;

use crate::arch::Arch;
use crate::ir::RawAddress;
use crate::lifter::resolve_language;
use crate::loader::{
    ImageAddress, ImageLayout, ImageSegment, ImageSegmentContents, Loadable, LoadableMetadata,
    LoaderError,
};
use crate::storage::segments::SegmentProperties;
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

    fn disassemble_snippet(language: &str, address: u64, bytes: &[u8]) -> anyhow::Result<String> {
        let shellcode = Shellcode::new(language, address, bytes)?;

        let mut lifter = shellcode.architecture().lifter();
        let mut offset = 0usize;
        let mut output = String::new();

        while offset < bytes.len() {
            let len = lifter
                .disassemble(address + offset as u64, &bytes[offset..], &mut output)
                .expect("valid");
            offset += len;
            output.push('\n');
        }

        Ok(output)
    }

    #[test]
    fn test_ppc_snippet() -> anyhow::Result<()> {
        let output = disassemble_snippet(
            "PowerPC:BE:32",
            0x1000,
            &[
                0x94, 0x21, 0xff, 0xe0, 0x93, 0xe1, 0x00, 0x1c, 0x7c, 0x3f, 0x0b, 0x78, 0x90, 0x7f,
                0x00, 0x18, 0x80, 0x9f, 0x00, 0x18, 0x7c, 0x64, 0x1a, 0x14, 0x4e, 0x80, 0x00, 0x20,
            ],
        )?;

        assert_eq!(
            output,
            r#"stwu r1,-0x20(r1)
stw r31,0x1c(r1)
or r31,r1,r1
stw r3,0x18(r31)
lwz r4,0x18(r31)
add r3,r4,r3
blr
"#
        );

        Ok(())
    }

    #[test]
    fn test_riscv_snippet() -> anyhow::Result<()> {
        let output = disassemble_snippet(
            "RISCV:LE:32",
            0x12ba,
            &[
                0x41, 0x11, 0x06, 0xc6, 0x22, 0xc4, 0x00, 0x08, 0x23, 0x2a, 0xa4, 0xfe,
            ],
        )?;

        assert_eq!(
            output,
            r#"c.addi sp,-0x10
c.swsp ra,0xc(sp)
c.swsp s0,0x8(sp)
c.addi4spn s0,sp,0x10
sw a0,-0xc(s0)
"#
        );

        Ok(())
    }

    #[test]
    fn test_riscv64_snippet() -> anyhow::Result<()> {
        let output = disassemble_snippet(
            "RISCV:LE:64",
            0x1442,
            &[
                0x01, 0x11, 0x06, 0xec, 0x22, 0xe8, 0x00, 0x10, 0x23, 0x26, 0xa4, 0xfe,
            ],
        )?;

        assert_eq!(
            output,
            r#"c.addi sp,-0x20
c.sdsp ra,0x18(sp)
c.sdsp s0,0x10(sp)
c.addi4spn s0,sp,0x20
sw a0,-0x14(s0)
"#
        );

        Ok(())
    }

    #[test]
    fn test_riscv_width_selects_distinct_language() -> anyhow::Result<()> {
        let encoding = [0x06, 0xec];

        assert_eq!(
            disassemble_snippet("RISCV:LE:32", 0x1000, &encoding)?,
            "c.fswsp ft1,0x18(sp)\n"
        );
        assert_eq!(
            disassemble_snippet("RISCV:LE:64", 0x1000, &encoding)?,
            "c.sdsp ra,0x18(sp)\n"
        );

        Ok(())
    }

    #[test]
    fn test_mips64_snippet() -> anyhow::Result<()> {
        let bytes = [
            0x67, 0xbd, 0xff, 0xe0, 0xff, 0xbf, 0x00, 0x18, 0xff, 0xbe, 0x00, 0x10, 0x03, 0xa0,
            0xf0, 0x25, 0x00, 0x80, 0x10, 0x25, 0xaf, 0xc2, 0x00, 0x0c,
        ];
        let expected = r#"daddiu sp, sp, -0x20
sd ra, 0x18(sp)
sd s8, 0x10(sp)
or s8, sp, zero
or v0, a0, zero
sw v0, 0xc(s8)
"#;

        assert_eq!(
            disassemble_snippet("MIPS:BE:64", 0x10650, &bytes)?,
            expected
        );

        let mut swapped = bytes;
        for word in swapped.chunks_mut(4) {
            word.reverse();
        }

        assert_eq!(
            disassemble_snippet("MIPS:LE:64", 0x10650, &swapped)?,
            expected
        );

        Ok(())
    }

    #[test]
    fn test_ppc64_a2alt_decodes_isa_3_0() -> anyhow::Result<()> {
        let darn = [0x7c, 0x61, 0x05, 0xe6];

        assert_eq!(
            disassemble_snippet("PowerPC:BE:64:A2ALT", 0x1000, &darn)?,
            "darn r3,0x1\n"
        );

        let base = Shellcode::new("PowerPC:BE:64:default", 0x1000u64, &darn[..])?;
        let mut lifter = base.architecture().lifter();
        let mut output = String::new();

        assert_eq!(lifter.disassemble(0x1000, &darn[..], &mut output), None);

        Ok(())
    }

    #[test]
    fn test_ppc64le_snippet() -> anyhow::Result<()> {
        let output = disassemble_snippet(
            "PowerPC:LE:64",
            0x10540,
            &[
                0xf4, 0xff, 0x61, 0x90, 0xf4, 0xff, 0xa1, 0x80, 0x14, 0x1a, 0x85, 0x7c, 0x00, 0x00,
                0x63, 0x80, 0x20, 0x00, 0x80, 0x4e,
            ],
        )?;

        assert_eq!(
            output,
            r#"stw r3,-0xc(r1)
lwz r5,-0xc(r1)
add r4,r5,r3
lwz r3,0x0(r3)
blr
"#
        );

        Ok(())
    }
}
