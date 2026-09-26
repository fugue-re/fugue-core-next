use object::read::macho::{MachHeader, MachOFile, MachOSection};
use object::{
    Architecture, Object, ObjectSection, ReadRef, Relocation, RelocationFlags, RelocationTarget,
};

use crate::arch::Arch;
use crate::ir::{RawAddress, SymbolIndex, TransientSymbolTable};
use crate::lifter::ContextHint;
use crate::loader::macho::extensions::RelocationContext;
use crate::loader::macho::{MACHO_SYMTAB_SELECTOR, macho_object_section_address};
use crate::loader::{ImageAddress, ImageSegmentContents, LoaderError};

mod aarch64;
mod generic;
mod x86_64;

fn macho_relocation_type(relocation: &Relocation) -> Option<u8> {
    let RelocationFlags::MachO { r_type, .. } = relocation.flags() else {
        tracing::warn!("unsupported relocation flags {relocation:?}");
        return None;
    };

    Some(r_type)
}

pub struct MachOSegmentRelocator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    macho: &'file MachOFile<'data, Mach, R>,
    arch: &'file Arch,
    base: RawAddress,
    preferred_base: RawAddress,
    symbols: &'file TransientSymbolTable<ImageAddress>,
    is_object: bool,
}

impl<'data, 'file, Mach, R> MachOSegmentRelocator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub fn new(
        macho: &'file MachOFile<'data, Mach, R>,
        arch: &'file Arch,
        base: RawAddress,
        preferred_base: RawAddress,
        symbols: &'file TransientSymbolTable<ImageAddress>,
        is_object: bool,
    ) -> Self {
        Self {
            macho,
            arch,
            base,
            preferred_base,
            symbols,
            is_object,
        }
    }

    pub fn apply(&self, bytes: &mut ImageSegmentContents<'data>) -> Result<(), LoaderError> {
        let start = bytes.address();
        let Some(last) = start.checked_add(bytes.size().saturating_sub(1)) else {
            return Err(LoaderError::address_overflow(start));
        };

        for section in self.macho.sections() {
            let Some(address) = self.section_address(&section) else {
                continue;
            };
            if address < start || address > last {
                continue;
            }
            self.apply_section(start, bytes, &section)?;
        }

        Ok(())
    }

    fn apply_section(
        &self,
        origin: RawAddress,
        bytes: &mut ImageSegmentContents<'data>,
        section: &MachOSection<'data, 'file, Mach, R>,
    ) -> Result<(), LoaderError> {
        let Some(section_address) = self.section_address(section) else {
            return Ok(());
        };
        let Some(section_offset) = section_address.checked_offset_from(origin) else {
            return Ok(());
        };

        for (offset, relocation) in section.relocations() {
            let Some(offset) = section_offset.checked_add(offset) else {
                return Err(LoaderError::address_overflow(origin));
            };
            self.apply_relocation(bytes, offset, &relocation)?;
        }

        Ok(())
    }

    fn apply_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        relocation: &Relocation,
    ) -> Result<(), LoaderError> {
        let Some(relocation_type) = macho_relocation_type(relocation) else {
            return Ok(());
        };
        let patch_address = bytes
            .address()
            .checked_add(offset)
            .ok_or_else(|| LoaderError::address_overflow(bytes.address()))?;
        let mut context = RelocationContext::new(
            self.macho,
            self.base,
            self.preferred_base,
            patch_address,
            offset,
            relocation_type,
            bytes,
        );

        if context.apply_relocation()? {
            return Ok(());
        }

        match self.macho.architecture() {
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => {
                self.apply_aarch64_relocation(context.segment_mut(), offset, relocation);
            }
            Architecture::X86_64 => {
                self.apply_x86_64_relocation(context.segment_mut(), offset, relocation);
            }
            _ => {
                self.apply_generic_relocation(context.segment_mut(), offset, relocation);
            }
        }

        Ok(())
    }

    fn section_address(&self, section: &MachOSection<'data, 'file, Mach, R>) -> Option<RawAddress> {
        if self.is_object {
            macho_object_section_address(self.macho, self.base, section.index().0)
        } else {
            self.base
                .checked_sub(self.preferred_base)
                .and_then(|slide| slide.checked_add(section.address()))
        }
    }

    fn resolve_relocation_target(&self, target: RelocationTarget) -> Option<u64> {
        match target {
            RelocationTarget::Absolute => Some(0),
            RelocationTarget::Section(index) => {
                if self.is_object {
                    macho_object_section_address(self.macho, self.base, index.0)
                        .map(|address| address.offset())
                } else {
                    let section = self.macho.section_by_index(index).ok()?;
                    Some(
                        (self.base - self.preferred_base)
                            .offset()
                            .wrapping_add(section.address()),
                    )
                }
            }
            RelocationTarget::Symbol(index) => self
                .symbols
                .get_by_index(SymbolIndex::new(MACHO_SYMTAB_SELECTOR, index.0))
                .map(|(_, symbol)| symbol.address().raw_offset()),
            _ => None,
        }
    }

    fn resolve_relocation_value(&self, relocation: &Relocation) -> Option<u64> {
        let target = self.resolve_relocation_target(relocation.target())?;
        let subtractor = relocation
            .subtractor()
            .and_then(|index| self.resolve_relocation_target(RelocationTarget::Symbol(index)))
            .unwrap_or_default();
        Some(target.wrapping_sub(subtractor))
    }

    fn mark_function_symbol(
        &self,
        address: impl Into<RawAddress>,
        bytes: &mut ImageSegmentContents<'data>,
    ) {
        let address = address.into();
        match self.arch.canonicalise_address(address) {
            Some((entry, context)) if entry != address => {
                bytes.add_function_hint(entry);
                bytes.add_mapping_hint(entry, ContextHint::code().with_context(context));
            }
            _ => bytes.add_function_hint(address),
        }
    }
}
