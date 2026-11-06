use object::read::macho::{MachHeader, MachOFile};
use object::{ReadRef, macho};

use crate::arch::Arch;
use crate::extension::{self, Registration};
use crate::ir::{Endian, RawAddress};
use crate::lifter::{LanguageId, LanguageSource};
use crate::loader::macho::MachOFileRepr;
use crate::loader::{ImageSegmentContents, LanguageVariantOverride, LoaderError};
use crate::types::{ATTRIBUTE_LANGUAGE_VARIANT, AttributeMap};

pub struct ImageContext<'a> {
    machine: u32,
    subtype: u32,
    endian: Endian,
    is_64: bool,
    flags: u32,
    file_type: u32,
    base: RawAddress,
    preferred_base: RawAddress,
    entry: Option<RawAddress>,
    attributes: &'a AttributeMap,
}

impl<'a> ImageContext<'a> {
    pub(crate) fn new(
        view: &MachOFileRepr<'_>,
        base: RawAddress,
        preferred_base: RawAddress,
        entry: Option<RawAddress>,
        attributes: &'a AttributeMap,
    ) -> Self {
        Self {
            machine: view.machine(),
            subtype: view.subtype(),
            endian: view.endian(),
            is_64: view.is_64(),
            flags: view.flags(),
            file_type: view.file_type(),
            base,
            preferred_base,
            entry,
            attributes,
        }
    }

    pub fn machine(&self) -> u32 {
        self.machine
    }

    pub fn subtype(&self) -> u32 {
        self.subtype
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn is_64(&self) -> bool {
        self.is_64
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn file_type(&self) -> u32 {
        self.file_type
    }

    pub fn base(&self) -> RawAddress {
        self.base
    }

    pub fn preferred_base(&self) -> RawAddress {
        self.preferred_base
    }

    pub fn entry(&self) -> Option<RawAddress> {
        self.entry
    }

    pub fn attributes(&self) -> &AttributeMap {
        self.attributes
    }

    pub fn resolve_architecture(&self) -> Result<Arch, LoaderError> {
        self.resolve_architecture_with(&LanguageSource::new())
    }

    pub fn resolve_architecture_with(
        &self,
        source: &LanguageSource<'_>,
    ) -> Result<Arch, LoaderError> {
        let mut matches = Vec::new();

        for resolver in extension::iter::<ArchResolver>() {
            if let Some(arch) = self.resolve_architecture_using(resolver, source)? {
                matches.push(arch);
            }
        }

        let arch = match matches.len() {
            0 => return Err(LoaderError::UnsupportedArch),
            1 => matches.remove(0),
            _ => {
                return Err(LoaderError::extension_with(
                    "ambiguous Mach-O architecture resolver",
                ));
            }
        };

        let Some(overrides) = self
            .attributes
            .get_attr::<LanguageVariantOverride>(ATTRIBUTE_LANGUAGE_VARIANT)
        else {
            return Ok(arch);
        };

        let language = arch.language();
        let Some(variant) = overrides.variant_for(language) else {
            return Ok(arch);
        };

        let id = LanguageId::new_with(
            language.processor(),
            language.is_big_endian(),
            language.bits(),
            Some(variant),
        );

        Arch::try_new(source.load(&id)?).map_err(LoaderError::extension)
    }

    pub fn resolve_architecture_using(
        &self,
        resolver: &ArchResolver,
        source: &LanguageSource<'_>,
    ) -> Result<Option<Arch>, LoaderError> {
        resolver.resolve_architecture(self, source)
    }
}

type ArchResolveFn =
    fn(&ImageContext<'_>, &LanguageSource<'_>) -> Result<Option<Arch>, LoaderError>;

pub struct ArchResolver {
    name: &'static str,
    resolve_architecture: ArchResolveFn,
}

impl ArchResolver {
    pub const fn new(name: &'static str, resolve_architecture: ArchResolveFn) -> Self {
        Self {
            name,
            resolve_architecture,
        }
    }

    pub fn resolve_architecture(
        &self,
        context: &ImageContext<'_>,
        source: &LanguageSource<'_>,
    ) -> Result<Option<Arch>, LoaderError> {
        (self.resolve_architecture)(context, source)
    }

    fn resolve_builtin(
        context: &ImageContext<'_>,
        source: &LanguageSource<'_>,
    ) -> Result<Option<Arch>, LoaderError> {
        let is_big = context.endian().is_big();
        let id = match context.machine() {
            macho::CPU_TYPE_ARM => LanguageId::new("ARM", is_big, 32),
            macho::CPU_TYPE_ARM64 => LanguageId::new("AARCH64", is_big, 64),
            macho::CPU_TYPE_ARM64_32 => LanguageId::new_with("AARCH64", is_big, 32, Some("ilp32")),
            macho::CPU_TYPE_MIPS => LanguageId::new("MIPS", is_big, 32),
            macho::CPU_TYPE_POWERPC => LanguageId::new("PowerPC", is_big, 32),
            macho::CPU_TYPE_POWERPC64 => LanguageId::new("PowerPC", is_big, 64),
            macho::CPU_TYPE_X86 => LanguageId::new("x86", is_big, 32),
            macho::CPU_TYPE_X86_64 => LanguageId::new("x86", is_big, 64),
            _ => return Ok(None),
        };

        let language = source.load(&id)?;
        let arch = Arch::try_new(language).map_err(LoaderError::extension)?;
        Ok(Some(arch))
    }
}

impl Registration for ArchResolver {
    fn name(&self) -> &'static str {
        self.name
    }
}

extension::collect!(ArchResolver);
extension::submit! {
    ArchResolver::new("macho-builtins", ArchResolver::resolve_builtin)
}

pub struct RelocationContext<'a, 'data> {
    machine: u32,
    base: RawAddress,
    preferred_base: RawAddress,
    patch_address: RawAddress,
    offset: u64,
    relocation_type: u8,
    segment: &'a mut ImageSegmentContents<'data>,
}

impl<'a, 'data> RelocationContext<'a, 'data> {
    pub(crate) fn new<Mach, R>(
        macho: &MachOFile<'data, Mach, R>,
        base: RawAddress,
        preferred_base: RawAddress,
        patch_address: RawAddress,
        offset: u64,
        relocation_type: u8,
        segment: &'a mut ImageSegmentContents<'data>,
    ) -> Self
    where
        Mach: MachHeader,
        R: ReadRef<'data>,
    {
        Self {
            machine: macho.macho_header().cputype(macho.endian()),
            base,
            preferred_base,
            patch_address,
            offset,
            relocation_type,
            segment,
        }
    }

    pub fn machine(&self) -> u32 {
        self.machine
    }

    pub fn base(&self) -> RawAddress {
        self.base
    }

    pub fn preferred_base(&self) -> RawAddress {
        self.preferred_base
    }

    pub fn patch_address(&self) -> RawAddress {
        self.patch_address
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn relocation_type(&self) -> u8 {
        self.relocation_type
    }

    pub fn segment(&self) -> &ImageSegmentContents<'data> {
        self.segment
    }

    pub fn segment_mut(&mut self) -> &mut ImageSegmentContents<'data> {
        self.segment
    }

    pub fn apply_relocation(&mut self) -> Result<bool, LoaderError> {
        for extension in extension::iter::<RelocationExtension>() {
            if self.apply_relocation_extension(extension)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn apply_relocation_extension(
        &mut self,
        extension: &RelocationExtension,
    ) -> Result<bool, LoaderError> {
        extension.apply(self)
    }
}

type RelocationExtensionFn = fn(&mut RelocationContext<'_, '_>) -> Result<bool, LoaderError>;

pub struct RelocationExtension {
    name: &'static str,
    apply: RelocationExtensionFn,
}

impl RelocationExtension {
    pub const fn new(name: &'static str, apply: RelocationExtensionFn) -> Self {
        Self { name, apply }
    }

    pub fn apply(&self, context: &mut RelocationContext<'_, '_>) -> Result<bool, LoaderError> {
        (self.apply)(context)
    }
}

impl Registration for RelocationExtension {
    fn name(&self) -> &'static str {
        self.name
    }
}

extension::collect!(RelocationExtension);
