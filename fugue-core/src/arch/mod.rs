use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};

use rkyv::bytecheck::CheckBytes;
use rkyv::rancor::{Fallible, Source};
use rkyv::ser::{Allocator, Writer};
use rkyv::traits::NoUndef;
use rkyv::{Archive, Archived, Deserialize, Place, Portable, Serialize};

use crate::il::pcode::Varnode;
use crate::ir::{Endian, ExternFunctionTemplate, RawAddress, Symbol};
use crate::lifter::{
    ContextHint, ContextSet, Disassembler, Language, Lifter, LiftingContext, resolve_language,
};
use crate::platform::Platform;
use crate::storage::entities::schema::ENTITY_ARCHITECTURE_ID;
use crate::storage::entities::{Entity, EntityId};

pub mod aarch64;
pub mod arm;
pub mod mips;
pub mod registry;
pub mod x86;
pub mod x86_64;

pub use registry::ArchError;

pub mod traits;
use traits::Arch as ArchT;
pub use traits::{Flag, FlagKind};

#[derive(Clone)]
#[repr(transparent)]
pub struct Arch(Box<dyn ArchT>);

impl Debug for Arch {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Arch")
            .field("language", self.0.language())
            .finish_non_exhaustive()
    }
}

impl Display for Arch {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.0.language().id())
    }
}

impl PartialEq for Arch {
    fn eq(&self, other: &Self) -> bool {
        self.0.language().id() == other.0.language().id()
    }
}

impl Eq for Arch {}

impl PartialOrd for Arch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Arch {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.language().id().cmp(other.0.language().id())
    }
}

impl Hash for Arch {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.language().id().hash(state);
    }
}

impl From<Box<dyn ArchT>> for Arch {
    fn from(arch: Box<dyn ArchT>) -> Self {
        Self(arch)
    }
}

impl From<&'static Language> for Arch {
    fn from(language: &'static Language) -> Self {
        Self::new(language)
    }
}

#[repr(transparent)]
pub struct ArchivedArch(Archived<String>);

unsafe impl Portable for ArchivedArch {}
unsafe impl NoUndef for ArchivedArch {}

unsafe impl<C: Fallible + ?Sized> CheckBytes<C> for ArchivedArch
where
    Archived<String>: CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { <Archived<String>>::check_bytes(value.cast(), context) }
    }
}

impl Archive for Arch {
    type Archived = ArchivedArch;
    type Resolver = <String as Archive>::Resolver;

    fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let out_inner = unsafe { out.cast_unchecked::<Archived<String>>() };
        self.0.language().to_string().resolve(resolver, out_inner);
    }
}

impl<S: Fallible + ?Sized + Allocator + Writer> Serialize<S> for Arch
where
    S::Error: Source,
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.0.language().to_string().serialize(serializer)
    }
}

impl<D: Fallible + ?Sized> Deserialize<Arch, D> for ArchivedArch
where
    D::Error: Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<Arch, D::Error> {
        let variant_str = Deserialize::<String, D>::deserialize(&self.0, deserializer)?;
        Ok(Arch::new(
            resolve_language(&variant_str).expect("invalid language variant"),
        ))
    }
}

impl Entity for Arch {
    const ID: EntityId = ENTITY_ARCHITECTURE_ID;
}

impl Arch {
    pub fn try_new(language: &'static Language) -> Result<Self, ArchError> {
        registry::provide_arch(language)
    }

    pub fn new(language: &'static Language) -> Self {
        Self::try_new(language).unwrap_or_else(|_| panic!("unsupported language: {language}"))
    }

    pub fn disassembler(&self) -> Disassembler {
        self.0.disassembler()
    }

    pub fn lifter(&self) -> Lifter {
        self.0.lifter()
    }

    pub fn endian(&self) -> Endian {
        self.0.endian()
    }

    pub fn canonicalise_address(
        &self,
        addr: impl Into<RawAddress>,
    ) -> Option<(RawAddress, ContextSet)> {
        self.0.canonicalise_address(addr.into())
    }

    pub fn canonicalise_address_with(
        &self,
        addr: impl Into<RawAddress>,
        context: &LiftingContext,
    ) -> Option<(RawAddress, ContextSet)> {
        self.0.canonicalise_address_with(addr.into(), context)
    }

    pub fn external_thunk_template(&self) -> ExternFunctionTemplate {
        self.0.external_function_template()
    }

    pub fn flags(&self) -> &[Flag] {
        self.0.flags()
    }

    pub fn frame_pointer(&self) -> Option<Varnode> {
        self.0.frame_pointer()
    }

    pub fn gprs(&self) -> &[Varnode] {
        self.0.gprs()
    }

    pub fn is_halt_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        self.0.is_halt_intrinsic(op, args)
    }

    pub fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        self.0.is_nonsense_pattern(bytes)
    }

    pub fn is_service_call(&self, op: u16, args: &[Varnode]) -> bool {
        self.0.is_service_call(op, args)
    }

    pub fn is_skip_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        self.0.is_skip_intrinsic(op, args)
    }

    pub fn is_trap_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        self.0.is_trap_intrinsic(op, args)
    }

    pub fn resolve_mapping_symbol(&self, symbol: impl Into<Symbol>) -> Option<ContextHint> {
        self.0.resolve_mapping_symbol(&symbol.into())
    }

    pub fn language(&self) -> &'static Language {
        self.0.language()
    }

    pub fn platform(&self) -> Platform {
        Platform::for_arch(self)
    }
}
