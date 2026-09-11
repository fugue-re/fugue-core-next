use object::read::elf::{ElfFile, ElfSection, FileHeader};
use object::{
    Architecture, Object, ObjectSection, ReadRef, Relocation, RelocationFlags, RelocationTarget,
};

use crate::arch::Arch;
use crate::ir::{RawAddress, SymbolEntry, SymbolIndex, TransientSymbolTable};
use crate::lifter::ContextHint;
use crate::loader::elf::extensions::RelocationContext;
use crate::loader::elf::{ELF_DYNSYM_SELECTOR, ELF_SYMTAB_SELECTOR};
use crate::loader::{ImageAddress, ImageSegmentContents, LoaderError};

pub mod generic;

pub mod aarch64;
pub mod arm;
pub mod mips;
pub mod mips64;
pub mod ppc;
pub mod ppc64;
pub mod riscv;
pub mod riscv64;
pub mod x86;
pub mod x86_64;

pub struct ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    elf: &'file ElfFile<'data, Elf, R>,
    arch: &'file Arch,
    base: RawAddress,
    symbols: &'file TransientSymbolTable<ImageAddress>,
    is_object: bool,
}

fn elf_relocation_type(reloc: &Relocation) -> Option<u32> {
    let RelocationFlags::Elf { r_type } = reloc.flags() else {
        tracing::warn!("unsupported relocation flags {reloc:?}");
        return None;
    };

    Some(r_type)
}

impl<'data, 'file, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub fn new(
        elf: &'file ElfFile<'data, Elf, R>,
        arch: &'file Arch,
        base: RawAddress,
        symbols: &'file TransientSymbolTable<ImageAddress>,
        is_object: bool,
    ) -> Self {
        Self {
            elf,
            arch,
            base,
            symbols,
            is_object,
        }
    }

    fn resolve_relocation_entry(
        &self,
        reloc: &Relocation,
        is_dynamic: bool,
    ) -> Option<&SymbolEntry<ImageAddress>> {
        let RelocationTarget::Symbol(index) = reloc.target() else {
            tracing::warn!("unsupported relocation target {reloc:?}");
            return None;
        };

        let external_selector = if self.is_object {
            ELF_SYMTAB_SELECTOR
        } else {
            ELF_DYNSYM_SELECTOR
        };

        if (is_dynamic || self.is_object)
            && let Some((id, entry)) = self
                .symbols
                .get_by_index(SymbolIndex::new(external_selector, index.0))
        {
            tracing::trace!("found external symbol {id:?} at {}", entry.address());
            return Some(entry);
        }

        if !is_dynamic
            && let Some((id, entry)) = self
                .symbols
                .get_by_index(SymbolIndex::new(ELF_SYMTAB_SELECTOR, index.0))
        {
            tracing::trace!("found symbol {id:?} at {}", entry.address());
            return Some(entry);
        }

        tracing::warn!(
            "attempting to resolve symbol that is not contained in either expected symbol table {index:?} (dynamic: {is_dynamic})",
        );

        None
    }

    pub fn apply(
        &self,
        origin: RawAddress,
        bytes: &mut ImageSegmentContents<'data>,
        sect: &ElfSection<'data, 'file, Elf, R>,
    ) -> Result<(), LoaderError> {
        self.apply_relocations(bytes, sect)?;
        self.apply_dynamic_relocations(origin, bytes)?;
        Ok(())
    }

    pub fn apply_relocations(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        sect: &ElfSection<'data, 'file, Elf, R>,
    ) -> Result<(), LoaderError> {
        for (off, rel) in sect.relocations() {
            tracing::trace!(
                "applying relocation {}+{off:#x} {:?} {rel:?}",
                bytes.address(),
                rel.kind()
            );

            self.apply_relocation(bytes, off, &rel, false)?;
        }

        Ok(())
    }

    pub fn apply_dynamic_relocations(
        &self,
        origin: RawAddress,
        bytes: &mut ImageSegmentContents<'data>,
    ) -> Result<(), LoaderError> {
        let Some(drels) = self.elf.dynamic_relocations() else {
            tracing::trace!("no dynamic relocations");
            return Ok(());
        };

        tracing::trace!(
            "attempting to apply {} dynamic relocations",
            self.elf
                .dynamic_relocations()
                .map(|d| d.count())
                .unwrap_or_default()
        );

        let Some(origin_offset) = origin.offset().checked_sub(self.base.offset()) else {
            tracing::warn!(
                "dynamic relocation origin {origin} is below image base {}",
                self.base
            );
            return Ok(());
        };
        let Some(origin_last_offset) = origin_offset.checked_add(bytes.size().saturating_sub(1))
        else {
            return Err(LoaderError::address_overflow(origin));
        };

        for (off, rel) in
            drels.filter(|(off, _)| *off >= origin_offset && *off <= origin_last_offset)
        {
            tracing::trace!("applying dynamic relocation at {}", RawAddress::from(off));

            let off = off - origin_offset;

            self.apply_relocation(bytes, off, &rel, true)?;
        }

        Ok(())
    }

    pub(crate) fn apply_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc: &Relocation,
        is_dynamic: bool,
    ) -> Result<(), LoaderError> {
        let patch_address = bytes.address() + offset;
        let relocation_type = match reloc.flags() {
            RelocationFlags::Elf { r_type } => Some(r_type),
            _ => None,
        };
        let mut context = RelocationContext::new(
            self.elf,
            self.base,
            patch_address,
            offset,
            relocation_type,
            is_dynamic,
            bytes,
        );

        if context.apply_relocation()? {
            return Ok(());
        }

        match self.elf.architecture() {
            Architecture::Aarch64 => {
                self.apply_aarch64_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            Architecture::Arm => {
                self.apply_arm_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            Architecture::I386 => {
                self.apply_x86_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            Architecture::Mips => {
                self.apply_mips_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            Architecture::Mips64 => {
                self.apply_mips64_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            Architecture::PowerPc => {
                self.apply_ppc_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            Architecture::PowerPc64 => {
                self.apply_ppc64_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            Architecture::Riscv32 => {
                self.apply_riscv_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            Architecture::Riscv64 => {
                self.apply_riscv64_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            Architecture::X86_64 => {
                self.apply_x86_64_relocation(context.segment_mut(), offset, reloc, is_dynamic);
            }
            arch => {
                tracing::warn!("unsupported architecture {arch:?} for relocation {reloc:?}");
            }
        }

        Ok(())
    }

    pub(crate) fn resolve_relocation_symbol(
        &self,
        reloc: &Relocation,
        is_dynamic: bool,
    ) -> Option<u64> {
        self.resolve_relocation_entry(reloc, is_dynamic)
            .map(|entry| entry.address().raw_offset())
    }

    pub(crate) fn mark_function_symbol(
        &self,
        address: impl Into<RawAddress>,
        bytes: &mut ImageSegmentContents<'data>,
    ) {
        let value = address.into();

        tracing::trace!("marking symbol {value} as function");

        match self.arch.canonicalise_address(value) {
            Some((entry, ctxset)) if entry != value => {
                bytes.add_function_hint(entry);
                bytes.add_mapping_hint(entry, ContextHint::code().with_context(ctxset));
            }
            _ => bytes.add_function_hint(value),
        }
    }

    pub(crate) fn mark_data_symbol(
        &self,
        reloc: &Relocation,
        is_dynamic: bool,
        bytes: &mut ImageSegmentContents<'data>,
    ) {
        let Some(entry) = self.resolve_relocation_entry(reloc, is_dynamic) else {
            return;
        };

        if !entry.is_data() {
            return;
        }

        let address = entry.address().raw_offset();

        tracing::trace!("marking symbol {address} as data");

        bytes.add_mapping_hint(address, ContextHint::data());
    }
}
