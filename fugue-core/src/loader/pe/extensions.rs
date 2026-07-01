use object::endian::LittleEndian;
use object::read::pe::{ImageNtHeaders, PeFile};
use object::{ReadRef, pe};

use crate::analysis::AnalysisError;
use crate::analysis::function::FunctionRecovery;
use crate::arch::Arch;
use crate::ir::{Address, Endian};
use crate::lifter::LanguageId;
use crate::lifter::dynamic::LanguageSource;
use crate::loader::pe::PeFileRepr;
use crate::loader::{ImageSegmentBytes, LoaderError, Pe};
use crate::registry::{self, Registration};
use crate::types::AttributeMap;

pub struct ImageContext<'a> {
    machine: u16,
    endian: Endian,
    is_64: bool,
    base: Address,
    preferred_base: Address,
    entry: Option<Address>,
    attributes: &'a AttributeMap,
}

impl<'a> ImageContext<'a> {
    pub(crate) fn new(
        view: &PeFileRepr<'_, '_>,
        base: Address,
        preferred_base: Address,
        entry: Option<Address>,
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
                "ambiguous PE architecture resolver",
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
    const NAME: &str = "pe-builtins";

    fn resolve_architecture(
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

pub struct AnalysisContext<'a> {
    pe: &'a Pe<'a>,
    arch: Arch,
    convention: Option<&'a str>,
}

impl<'a> AnalysisContext<'a> {
    pub(crate) fn new(pe: &'a Pe<'a>, arch: Arch, convention: Option<&'a str>) -> Self {
        Self {
            pe,
            arch,
            convention,
        }
    }

    pub fn pe(&self) -> &'a Pe<'a> {
        self.pe
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
    preferred_base: Address,
    patch_address: Address,
    offset: u64,
    relocation_type: u16,
    segment: &'a mut ImageSegmentBytes<'data>,
}

impl<'a, 'data> RelocationContext<'a, 'data> {
    pub(crate) fn new<Headers, R>(
        pe: &PeFile<'data, Headers, R>,
        base: Address,
        preferred_base: Address,
        patch_address: Address,
        offset: u64,
        relocation_type: u16,
        segment: &'a mut ImageSegmentBytes<'data>,
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

    pub fn base(&self) -> Address {
        self.base
    }

    pub fn preferred_base(&self) -> Address {
        self.preferred_base
    }

    pub fn patch_address(&self) -> Address {
        self.patch_address
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn relocation_type(&self) -> u16 {
        self.relocation_type
    }

    pub fn segment(&self) -> &ImageSegmentBytes<'data> {
        self.segment
    }

    pub fn segment_mut(&mut self) -> &mut ImageSegmentBytes<'data> {
        self.segment
    }

    pub fn apply_relocation(&mut self) -> Result<bool, LoaderError> {
        let mut applied = false;

        for handler in registry::iter::<RelocationHandler>() {
            if self.apply_relocation_with(handler)? {
                if applied {
                    return Err(LoaderError::extension_with(
                        "ambiguous PE relocation handler",
                    ));
                }
                applied = true;
            }
        }

        Ok(applied)
    }

    fn apply_relocation_with(&mut self, handler: &RelocationHandler) -> Result<bool, LoaderError> {
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
