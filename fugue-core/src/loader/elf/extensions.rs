use object::read::elf::{ElfFile, FileHeader};
use object::{ReadRef, elf};

use crate::arch::Arch;
use crate::extension::{self, Registration};
use crate::ir::RawAddress;
use crate::lifter::{LanguageId, LanguageSource};
use crate::loader::elf::ElfFileRepr;
use crate::loader::{ImageSegmentContents, LoaderError};
use crate::types::AttributeMap;

pub struct ImageContext<'a> {
    is_64: bool,
    is_be: bool,
    machine: u16,
    flags: u32,
    base: RawAddress,
    preferred_base: RawAddress,
    entry: Option<RawAddress>,
    attributes: &'a AttributeMap,
}

impl<'a> ImageContext<'a> {
    pub(crate) fn new(
        view: &ElfFileRepr<'_, '_>,
        base: RawAddress,
        preferred_base: RawAddress,
        entry: Option<RawAddress>,
        attributes: &'a AttributeMap,
    ) -> Self {
        Self {
            is_64: view.is_64(),
            is_be: view.is_big_endian(),
            machine: view.machine(),
            flags: view.flags(),
            base,
            preferred_base,
            entry,
            attributes,
        }
    }

    pub fn is_64(&self) -> bool {
        self.is_64
    }

    pub fn is_big_endian(&self) -> bool {
        self.is_be
    }

    pub fn machine(&self) -> u16 {
        self.machine
    }

    pub fn flags(&self) -> u32 {
        self.flags
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

        match matches.len() {
            0 => Err(LoaderError::UnsupportedArch),
            1 => Ok(matches.remove(0)),
            _ => Err(LoaderError::extension_with(
                "ambiguous ELF architecture resolver",
            )),
        }
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
        let is_be = context.is_big_endian();
        let variant = match context.machine() {
            elf::EM_AARCH64 if context.is_64() => None,
            elf::EM_ARM => context
                .entry()
                .and_then(|entry| (entry.offset() & 1 == 1).then_some("v8T")),
            elf::EM_386 => None,
            elf::EM_MIPS if !context.is_64() => None,
            elf::EM_X86_64 => None,
            _ => return Ok(None),
        };

        let id = match context.machine() {
            elf::EM_AARCH64 => LanguageId::new_with("AARCH64", is_be, 64, variant),
            elf::EM_ARM => LanguageId::new_with("ARM", is_be, 32, variant),
            elf::EM_386 => LanguageId::new_with("x86", false, 32, variant),
            elf::EM_MIPS => LanguageId::new_with("MIPS", is_be, 32, variant),
            elf::EM_X86_64 => LanguageId::new_with("x86", false, 64, variant),
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
    ArchResolver::new("elf-builtins", ArchResolver::resolve_builtin)
}

pub struct RelocationContext<'a, 'data> {
    machine: u16,
    base: RawAddress,
    patch_address: RawAddress,
    offset: u64,
    relocation_type: Option<u32>,
    is_dynamic: bool,
    segment: &'a mut ImageSegmentContents<'data>,
}

impl<'a, 'data> RelocationContext<'a, 'data> {
    pub(crate) fn new<Header, R>(
        elf: &ElfFile<'data, Header, R>,
        base: RawAddress,
        patch_address: RawAddress,
        offset: u64,
        relocation_type: Option<u32>,
        is_dynamic: bool,
        segment: &'a mut ImageSegmentContents<'data>,
    ) -> Self
    where
        Header: FileHeader,
        R: ReadRef<'data>,
    {
        Self {
            machine: elf.elf_header().e_machine(elf.endian()),
            base,
            patch_address,
            offset,
            relocation_type,
            is_dynamic,
            segment,
        }
    }

    pub fn machine(&self) -> u16 {
        self.machine
    }

    pub fn base(&self) -> RawAddress {
        self.base
    }

    pub fn patch_address(&self) -> RawAddress {
        self.patch_address
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn relocation_type(&self) -> Option<u32> {
        self.relocation_type
    }

    pub fn is_dynamic(&self) -> bool {
        self.is_dynamic
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
