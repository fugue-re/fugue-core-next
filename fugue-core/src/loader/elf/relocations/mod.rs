use object::read::elf::{ElfFile, ElfSection, FileHeader};
use object::{
    Architecture, Object, ObjectSection, ReadRef, Relocation, RelocationFlags, RelocationTarget,
};

use crate::ir::{Address, IndexedSymbolTable, SymbolIndex};
use crate::loader::elf::{ELF_DYNSYM_SELECTOR, ELF_SYMTAB_SELECTOR};
use crate::loader::{LoadableSegment, LoaderError};

pub mod generic;

pub mod aarch64;
pub mod arm;

pub mod x86;
pub mod x86_64;

pub struct ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    elf: &'file ElfFile<'data, Elf, R>,
    base: Address,
    symbols: &'file IndexedSymbolTable,
    is_object: bool,
}

impl<'data, 'file, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub fn new(
        elf: &'file ElfFile<'data, Elf, R>,
        symbols: &'file IndexedSymbolTable,
        is_object: bool,
        base: Address,
    ) -> Self {
        Self {
            elf,
            base,
            symbols,
            is_object,
        }
    }

    pub fn apply(
        &self,
        origin: impl Into<Address>,
        lsegm: &mut LoadableSegment<'data>,
        sect: &ElfSection<'data, 'file, Elf, R>,
    ) -> Result<(), LoaderError> {
        let origin = origin.into();
        self.apply_relocations(origin, lsegm, sect)?;
        self.apply_dynamic_relocations(origin, lsegm)?;
        Ok(())
    }

    pub fn apply_relocations(
        &self,
        _origin: impl Into<Address>,
        lsegm: &mut LoadableSegment<'data>,
        sect: &ElfSection<'data, 'file, Elf, R>,
    ) -> Result<(), LoaderError> {
        let _origin = _origin.into();
        for (off, rel) in sect.relocations() {
            tracing::trace!(
                "applying relocation {}+{off:#x} {:?} {rel:?}",
                lsegm.address(),
                rel.kind()
            );

            self.apply_relocation(lsegm, off, &rel, false);
        }

        Ok(())
    }

    pub fn apply_dynamic_relocations(
        &self,
        origin: impl Into<Address>,
        lsegm: &mut LoadableSegment<'data>,
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

        let origin = origin.into();
        let Some(origin_offset) = origin.offset().checked_sub(self.base.offset()) else {
            tracing::warn!(
                "dynamic relocation origin {origin} is below image base {}",
                self.base
            );
            return Ok(());
        };
        let Some(origin_last_offset) =
            origin_offset.checked_add(lsegm.len().saturating_sub(1) as u64)
        else {
            return Err(LoaderError::address_overflow(origin));
        };

        for (off, rel) in
            drels.filter(|(off, _)| *off >= origin_offset && *off <= origin_last_offset)
        {
            tracing::trace!("applying dynamic relocation at {}", Address::from(off));

            // Compute offset in the segment
            let off = off - origin_offset;

            self.apply_relocation(lsegm, off, &rel, true);
        }

        Ok(())
    }

    pub(crate) fn apply_relocation(
        &self,
        lsegm: &mut LoadableSegment<'data>,
        offset: u64,
        reloc: &Relocation,
        is_dynamic: bool,
    ) {
        match self.elf.architecture() {
            Architecture::Aarch64 => {
                self.apply_aarch64_relocation(lsegm, offset, reloc, is_dynamic);
            }
            Architecture::Arm => {
                self.apply_arm_relocation(lsegm, offset, reloc, is_dynamic);
            }
            Architecture::I386 => {
                self.apply_x86_relocation(lsegm, offset, reloc, is_dynamic);
            }
            Architecture::X86_64 => {
                self.apply_x86_64_relocation(lsegm, offset, reloc, is_dynamic);
            }
            arch => {
                tracing::warn!("unsupported architecture {arch:?} for relocation {reloc:?}");
            }
        }
    }

    pub(crate) fn elf_relocation_type(&self, reloc: &Relocation) -> Option<u32> {
        let RelocationFlags::Elf { r_type } = reloc.flags() else {
            tracing::warn!("unsupported relocation flags {reloc:?}");
            return None;
        };

        Some(r_type)
    }

    pub(crate) fn resolve_relocation_symbol(
        &self,
        reloc: &Relocation,
        is_dynamic: bool,
    ) -> Option<u64> {
        let RelocationTarget::Symbol(index) = reloc.target() else {
            tracing::warn!("unsupported relocation target {reloc:?}");
            return None;
        };

        let extern_selector = if self.is_object {
            ELF_SYMTAB_SELECTOR
        } else {
            ELF_DYNSYM_SELECTOR
        };

        // NOTE: this should only be checked if we are processing dynamic relocations?
        if (is_dynamic || self.is_object)
            // && let Some(target) = self.externs.as_ref().and_then(|e| e.get_address(index.0))
            && let Some((id, entry)) = self.symbols.get_by_index(SymbolIndex::new(extern_selector, index.0))
        {
            let address = entry.address();
            tracing::trace!("found external symbol {id:?} at {address}");
            return Some(address.offset());
        }

        if !is_dynamic && // let Some(target) = self.symbols.get_address(index.0) {
            let Some((id, entry)) = self.symbols.get_by_index(SymbolIndex::new(ELF_SYMTAB_SELECTOR, index.0))
        {
            let address = entry.address();
            tracing::trace!("found symbol {id:?} at {address}");
            return Some(address.offset());
        }

        tracing::warn!(
            "attempting to resolve symbol that is not contained in either expected symbol table {index:?} (dynamic: {is_dynamic})",
        );

        None

        // TODO: review this logic--it's not clear we need it.
        //
        // NOTE: in this case, we need to compute the address + our base
        // for object files, this base address will be the beginning of the
        // loaded segment containing it, probably we should save the section
        // map computed in `elf_symbols`?
        //
        // let table = if is_dynamic {
        //    self.elf.dynamic_symbol_table()?
        // } else {
        //    self.elf.symbol_table()?
        // };
        //
        // let symbol = table.symbol_by_index(index).ok()?;
        //
        // Some(symbol.address())
    }

    pub(crate) fn mark_function_symbol(
        &self,
        address: impl Into<Address>,
        lsegm: &mut LoadableSegment<'data>,
    ) {
        let address = address.into();

        tracing::trace!("marking symbol {address} as function");

        lsegm.add_function_hint(address);

        /*
        if self.externs.as_ref().map_or(false, |externs| {
            externs.update_symbol_properties(address, |props| props | SymbolProperties::FUNCTION)
        }) {
            return;
        }

        let Some(entries) = self.symbols.get_by_address_mut(address) else {
            tracing::warn!("attempting to mark non-existing symbol {address} as function");
            return;
        };

        entries.for_each(|(_, entry)| {
            entry.mark_as_function();
        });
        */
    }
}
