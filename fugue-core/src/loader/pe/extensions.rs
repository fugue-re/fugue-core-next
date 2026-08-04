use object::endian::LittleEndian;
use object::read::pe::{ImageNtHeaders, PeFile};
use object::{ReadRef, pe};

use crate::analysis::AnalysisError;
use crate::analysis::function::FunctionRecovery;
use crate::arch::Arch;
use crate::extension::{self, Registration};
use crate::ir::{Endian, RawAddress};
use crate::lifter::{LanguageId, LanguageSource};
use crate::loader::pe::PeFileRepr;
use crate::loader::{ImageSegmentContents, LoaderError, Pe};
use crate::platform::{CallingConvention, Platform};
use crate::types::AttributeMap;

pub struct ImageContext<'a> {
    machine: u16,
    endian: Endian,
    is_64: bool,
    base: RawAddress,
    preferred_base: RawAddress,
    entry: Option<RawAddress>,
    attributes: &'a AttributeMap,
}

impl<'a> ImageContext<'a> {
    pub(crate) fn new(
        view: &PeFileRepr<'_, '_>,
        base: RawAddress,
        preferred_base: RawAddress,
        entry: Option<RawAddress>,
        attributes: &'a AttributeMap,
    ) -> Self {
        Self {
            machine: view.machine(),
            endian: Endian::Little,
            is_64: view.is_64(),
            base,
            preferred_base,
            entry,
            attributes,
        }
    }

    pub fn machine(&self) -> u16 {
        self.machine
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn is_64(&self) -> bool {
        self.is_64
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
                "ambiguous PE architecture resolver",
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
        let variant = match context.machine() {
            pe::IMAGE_FILE_MACHINE_ARM
            | pe::IMAGE_FILE_MACHINE_THUMB
            | pe::IMAGE_FILE_MACHINE_ARMNT => context
                .entry()
                .and_then(|entry| (entry.offset() & 1 == 1).then_some("v8T")),
            pe::IMAGE_FILE_MACHINE_ARM64 => None,
            pe::IMAGE_FILE_MACHINE_I386 => None,
            pe::IMAGE_FILE_MACHINE_AMD64 => None,
            pe::IMAGE_FILE_MACHINE_R3000
            | pe::IMAGE_FILE_MACHINE_R4000
            | pe::IMAGE_FILE_MACHINE_R10000
            | pe::IMAGE_FILE_MACHINE_WCEMIPSV2 => None,
            _ => return Ok(None),
        };

        let id = match context.machine() {
            pe::IMAGE_FILE_MACHINE_ARM
            | pe::IMAGE_FILE_MACHINE_THUMB
            | pe::IMAGE_FILE_MACHINE_ARMNT => LanguageId::new_with("ARM", false, 32, variant),
            pe::IMAGE_FILE_MACHINE_ARM64 => LanguageId::new_with("AARCH64", false, 64, variant),
            pe::IMAGE_FILE_MACHINE_I386 => LanguageId::new_with("x86", false, 32, variant),
            pe::IMAGE_FILE_MACHINE_AMD64 => LanguageId::new_with("x86", false, 64, variant),
            pe::IMAGE_FILE_MACHINE_R3000
            | pe::IMAGE_FILE_MACHINE_R4000
            | pe::IMAGE_FILE_MACHINE_R10000
            | pe::IMAGE_FILE_MACHINE_WCEMIPSV2 => LanguageId::new_with("MIPS", false, 32, variant),
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
    ArchResolver::new("pe-builtins", ArchResolver::resolve_builtin)
}

pub struct AnalysisContext<'a> {
    pe: &'a Pe<'a>,
    arch: Arch,
    platform: Platform,
}

impl<'a> AnalysisContext<'a> {
    pub(crate) fn new(pe: &'a Pe<'a>, arch: Arch, platform: Platform) -> Self {
        Self { pe, arch, platform }
    }

    pub fn pe(&self) -> &'a Pe<'a> {
        self.pe
    }

    pub fn arch(&self) -> &Arch {
        &self.arch
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub fn calling_convention(&self) -> CallingConvention {
        self.platform.calling_convention()
    }

    pub fn apply_function_recovery_extensions(
        &self,
        recovery: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        for handler in extension::iter::<FunctionRecoveryHandler>() {
            self.apply_function_recovery_extension(handler, recovery)?;
        }

        Ok(())
    }

    pub fn apply_function_recovery_extension(
        &self,
        handler: &FunctionRecoveryHandler,
        recovery: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        handler.apply(self, recovery)
    }
}

type FunctionRecoveryHandlerFn =
    fn(&AnalysisContext<'_>, &mut FunctionRecovery) -> Result<(), AnalysisError>;

pub struct FunctionRecoveryHandler {
    name: &'static str,
    apply: FunctionRecoveryHandlerFn,
}

impl FunctionRecoveryHandler {
    pub const fn new(name: &'static str, apply: FunctionRecoveryHandlerFn) -> Self {
        Self { name, apply }
    }

    pub fn apply(
        &self,
        context: &AnalysisContext<'_>,
        recovery: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        (self.apply)(context, recovery)
    }
}

impl Registration for FunctionRecoveryHandler {
    fn name(&self) -> &'static str {
        self.name
    }
}

extension::collect!(FunctionRecoveryHandler);

pub struct RelocationContext<'a, 'data> {
    machine: u16,
    base: RawAddress,
    preferred_base: RawAddress,
    patch_address: RawAddress,
    offset: u64,
    relocation_type: u16,
    segment: &'a mut ImageSegmentContents<'data>,
}

impl<'a, 'data> RelocationContext<'a, 'data> {
    pub(crate) fn new<Headers, R>(
        pe: &PeFile<'data, Headers, R>,
        base: RawAddress,
        preferred_base: RawAddress,
        patch_address: RawAddress,
        offset: u64,
        relocation_type: u16,
        segment: &'a mut ImageSegmentContents<'data>,
    ) -> Self
    where
        Headers: ImageNtHeaders,
        R: ReadRef<'data>,
    {
        Self {
            machine: pe.nt_headers().file_header().machine.get(LittleEndian),
            base,
            preferred_base,
            patch_address,
            offset,
            relocation_type,
            segment,
        }
    }

    pub fn machine(&self) -> u16 {
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

    pub fn relocation_type(&self) -> u16 {
        self.relocation_type
    }

    pub fn segment(&self) -> &ImageSegmentContents<'data> {
        self.segment
    }

    pub fn segment_mut(&mut self) -> &mut ImageSegmentContents<'data> {
        self.segment
    }

    pub fn apply_relocation(&mut self) -> Result<bool, LoaderError> {
        for handler in extension::iter::<RelocationHandler>() {
            if self.apply_relocation_with(handler)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn apply_relocation_with(&mut self, handler: &RelocationHandler) -> Result<bool, LoaderError> {
        handler.apply_relocation(self)
    }
}

type RelocationApplyFn = fn(&mut RelocationContext<'_, '_>) -> Result<bool, LoaderError>;

pub struct RelocationHandler {
    name: &'static str,
    apply_relocation: RelocationApplyFn,
}

impl RelocationHandler {
    pub const fn new(name: &'static str, apply_relocation: RelocationApplyFn) -> Self {
        Self {
            name,
            apply_relocation,
        }
    }

    pub fn apply_relocation(
        &self,
        context: &mut RelocationContext<'_, '_>,
    ) -> Result<bool, LoaderError> {
        (self.apply_relocation)(context)
    }
}

impl Registration for RelocationHandler {
    fn name(&self) -> &'static str {
        self.name
    }
}

extension::collect!(RelocationHandler);
