use object::read::elf::{ElfFile, FileHeader};
use object::{ReadRef, elf};

use crate::analysis::AnalysisError;
use crate::analysis::function::FunctionRecovery;
use crate::arch::Arch;
use crate::ir::Address;
use crate::lifter::LanguageId;
use crate::lifter::dynamic::LanguageSource;
use crate::loader::elf::ElfFileRepr;
use crate::loader::{Elf, LoadableSegment, LoaderError};
use crate::registry::{self, Registration};
use crate::types::AttributeMap;

pub struct ImageContext<'a> {
    is_64: bool,
    is_be: bool,
    machine: u16,
    flags: u32,
    base: Address,
    preferred_base: Address,
    entry: Option<Address>,
    attributes: &'a AttributeMap,
}

impl<'a> ImageContext<'a> {
    pub(crate) fn new(
        view: &ElfFileRepr<'_, '_>,
        base: Address,
        preferred_base: Address,
        entry: Option<Address>,
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

    pub fn base(&self) -> Address {
        self.base
    }

    pub fn preferred_base(&self) -> Address {
        self.preferred_base
    }

    pub fn entry(&self) -> Option<Address> {
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

        for resolver in registry::iter::<ArchResolver>() {
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
        (resolver.resolve_architecture)(self, source)
    }
}

type ArchResolveFn =
    fn(&ImageContext<'_>, &LanguageSource<'_>) -> Result<Option<Arch>, LoaderError>;

pub struct ArchResolver {
    pub name: &'static str,
    pub resolve_architecture: ArchResolveFn,
}

impl Registration for ArchResolver {
    fn name(&self) -> &'static str {
        self.name
    }
}

registry::collect!(ArchResolver);

#[fugue_core::extension]
impl ArchResolver {
    const NAME: &str = "elf-builtins";

    fn resolve_architecture(
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

pub struct AnalysisContext<'a> {
    elf: &'a Elf<'a>,
    arch: Arch,
    convention: Option<&'a str>,
}

impl<'a> AnalysisContext<'a> {
    pub(crate) fn new(elf: &'a Elf<'a>, arch: Arch, convention: Option<&'a str>) -> Self {
        Self {
            elf,
            arch,
            convention,
        }
    }

    pub fn elf(&self) -> &'a Elf<'a> {
        self.elf
    }

    pub fn arch(&self) -> &Arch {
        &self.arch
    }

    pub fn convention(&self) -> Option<&'a str> {
        self.convention
    }

    pub fn configure_function_recovery(
        &self,
        recovery: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        for handler in registry::iter::<FunctionRecoveryHandler>() {
            self.configure_function_recovery_with(handler, recovery)?;
        }

        Ok(())
    }

    pub fn configure_function_recovery_with(
        &self,
        handler: &FunctionRecoveryHandler,
        recovery: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        (handler.configure_function_recovery)(self, recovery)
    }
}

type FunctionRecoveryConfigureFn =
    fn(&AnalysisContext<'_>, &mut FunctionRecovery) -> Result<(), AnalysisError>;

pub struct FunctionRecoveryHandler {
    pub name: &'static str,
    pub configure_function_recovery: FunctionRecoveryConfigureFn,
}

impl Registration for FunctionRecoveryHandler {
    fn name(&self) -> &'static str {
        self.name
    }
}

registry::collect!(FunctionRecoveryHandler);

pub struct RelocationContext<'a, 'data> {
    machine: u16,
    base: Address,
    patch_address: Address,
    offset: u64,
    relocation_type: Option<u32>,
    is_dynamic: bool,
    segment: &'a mut LoadableSegment<'data>,
}

impl<'a, 'data> RelocationContext<'a, 'data> {
    pub(crate) fn new<Header, R>(
        elf: &ElfFile<'data, Header, R>,
        base: Address,
        patch_address: Address,
        offset: u64,
        relocation_type: Option<u32>,
        is_dynamic: bool,
        segment: &'a mut LoadableSegment<'data>,
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

    pub fn base(&self) -> Address {
        self.base
    }

    pub fn patch_address(&self) -> Address {
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

    pub fn segment(&self) -> &LoadableSegment<'data> {
        self.segment
    }

    pub fn segment_mut(&mut self) -> &mut LoadableSegment<'data> {
        self.segment
    }

    pub fn apply_relocation(&mut self) -> Result<bool, LoaderError> {
        let mut applied = false;

        for handler in registry::iter::<RelocationHandler>() {
            if self.apply_relocation_with(handler)? {
                if applied {
                    return Err(LoaderError::extension_with(
                        "ambiguous ELF relocation handler",
                    ));
                }
                applied = true;
            }
        }

        Ok(applied)
    }

    pub fn apply_relocation_with(
        &mut self,
        handler: &RelocationHandler,
    ) -> Result<bool, LoaderError> {
        (handler.apply_relocation)(self)
    }
}

type RelocationApplyFn = fn(&mut RelocationContext<'_, '_>) -> Result<bool, LoaderError>;

pub struct RelocationHandler {
    pub name: &'static str,
    pub apply_relocation: RelocationApplyFn,
}

impl Registration for RelocationHandler {
    fn name(&self) -> &'static str {
        self.name
    }
}

registry::collect!(RelocationHandler);
