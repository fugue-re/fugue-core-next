use std::fmt::{self, Display, Formatter};

pub mod non_returning;
pub mod posix;
pub mod windows;

use ustr::Ustr;

use crate::arch::Arch;
use crate::ir::Endian;
use crate::storage::entities::schema::ENTITY_PLATFORM_ID;
use crate::storage::entities::{Entity, EntityId};

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum Format {
    Elf,
    MachO,
    Pe,
    #[default]
    Unknown,
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum OperatingSystem {
    FreeBsd,
    Linux,
    Macos,
    None,
    Uefi,
    #[default]
    Unknown,
    Windows,
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum Abi {
    Eabi,
    Gnu,
    Msvc,
    Musl,
    SysV,
    #[default]
    Unknown,
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum CallingConvention {
    Aapcs,
    Cdecl,
    #[default]
    Default,
    Fastcall,
    Gcc,
    Stdcall,
    SysV,
    Unknown,
    Win64,
}

impl CallingConvention {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Aapcs => "aapcs",
            Self::Cdecl => "cdecl",
            Self::Default => "default",
            Self::Fastcall => "fastcall",
            Self::Gcc => "gcc",
            Self::Stdcall => "stdcall",
            Self::SysV => "sysv",
            Self::Unknown => "unknown",
            Self::Win64 => "win64",
        }
    }
}

impl Display for CallingConvention {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct TypeLayout {
    endian: Endian,
    pointer_size: usize,
}

impl TypeLayout {
    pub const fn new(pointer_size: usize, endian: Endian) -> Self {
        Self {
            endian,
            pointer_size,
        }
    }

    pub fn for_arch(arch: &Arch) -> Self {
        Self::new(arch.language().address_size(), arch.endian())
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Platform {
    abi: Abi,
    calling_convention: CallingConvention,
    compiler_spec_id: Ustr,
    format: Format,
    os: OperatingSystem,
    type_layout: TypeLayout,
}

impl Entity for Platform {
    const ID: EntityId = ENTITY_PLATFORM_ID;
}

impl Platform {
    pub fn new(type_layout: TypeLayout) -> Self {
        Self {
            abi: Abi::Unknown,
            calling_convention: CallingConvention::Default,
            compiler_spec_id: Ustr::from("default"),
            format: Format::Unknown,
            os: OperatingSystem::Unknown,
            type_layout,
        }
    }

    pub fn for_arch(arch: &Arch) -> Self {
        Self::new(TypeLayout::for_arch(arch))
    }

    pub fn abi(&self) -> Abi {
        self.abi
    }

    pub fn calling_convention(&self) -> CallingConvention {
        self.calling_convention
    }

    pub(crate) fn compiler_spec_id(&self) -> &'static str {
        self.compiler_spec_id.as_str()
    }

    pub fn format(&self) -> Format {
        self.format
    }

    pub fn os(&self) -> OperatingSystem {
        self.os
    }

    pub fn type_layout(&self) -> TypeLayout {
        self.type_layout
    }

    pub fn set_abi(&mut self, abi: Abi) {
        self.abi = abi;
    }

    pub fn set_calling_convention(&mut self, calling_convention: CallingConvention) {
        self.calling_convention = calling_convention;
    }

    pub(crate) fn set_compiler_spec_id(&mut self, compiler_spec_id: impl AsRef<str>) {
        self.compiler_spec_id = Ustr::from(compiler_spec_id.as_ref());
    }

    pub fn set_format(&mut self, format: Format) {
        self.format = format;
    }

    pub fn set_os(&mut self, os: OperatingSystem) {
        self.os = os;
    }

    pub fn set_type_layout(&mut self, type_layout: TypeLayout) {
        self.type_layout = type_layout;
    }

    pub fn with_abi(mut self, abi: Abi) -> Self {
        self.set_abi(abi);
        self
    }

    pub fn with_calling_convention(mut self, calling_convention: CallingConvention) -> Self {
        self.set_calling_convention(calling_convention);
        self
    }

    pub(crate) fn with_compiler_spec_id(mut self, compiler_spec_id: impl AsRef<str>) -> Self {
        self.set_compiler_spec_id(compiler_spec_id);
        self
    }

    pub fn with_format(mut self, format: Format) -> Self {
        self.set_format(format);
        self
    }

    pub fn with_os(mut self, os: OperatingSystem) -> Self {
        self.set_os(os);
        self
    }

    pub fn with_type_layout(mut self, type_layout: TypeLayout) -> Self {
        self.set_type_layout(type_layout);
        self
    }
}
