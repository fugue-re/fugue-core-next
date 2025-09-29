use object::read::elf::{ElfFile, ElfSection, FileHeader};
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, ReadRef, Relocation,
    RelocationFlags, RelocationKind, RelocationTarget,
};

use crate::ir::Address;
use crate::loader::symbols::SymbolProperties;
use crate::loader::{ExternSymbols, LoadableSegment, LoaderError, LocalSymbols};

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
    locals: &'file LocalSymbols,
    externs: Option<&'file ExternSymbols>,
}

impl<'data, 'file, 'segments, Elf, R> ElfSegmentRelocator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub fn new(
        elf: &'file ElfFile<'data, Elf, R>,
        locals: &'file LocalSymbols,
        externs: Option<&'file ExternSymbols>,
    ) -> Self {
        Self {
            elf,
            locals,
            externs,
        }
    }

    pub fn apply(
        &self,
        lsegm: &mut LoadableSegment<'data>,
        sect: &ElfSection<'data, 'file, Elf, R>,
    ) -> Result<(), LoaderError> {
        self.apply_relocations(lsegm, sect)?;
        self.apply_dynamic_relocations(lsegm)?;
        Ok(())
    }

    pub fn apply_relocations(
        &self,
        lsegm: &mut LoadableSegment<'data>,
        sect: &ElfSection<'data, 'file, Elf, R>,
    ) -> Result<(), LoaderError> {
        for (off, rel) in sect.relocations() {
            tracing::trace!(
                "applying relocation {}+{off:#x} {:?} {rel:?}",
                lsegm.address(),
                rel.kind()
            );

            match rel.kind() {
                RelocationKind::Unknown => {
                    let RelocationFlags::Elf { r_type } = rel.flags() else {
                        // NOTE: we could probably panic here
                        continue;
                    };

                    match self.elf.architecture() {
                        Architecture::X86_64 => {
                            self.apply_x86_64_relocation(lsegm, off, &rel, r_type, false);
                        }
                        arch => {
                            tracing::warn!(
                                "unsupported architecture {arch:?} for relocation {:?}",
                                rel.kind()
                            );
                        }
                    }
                }
                kind => {
                    self.apply_generic_relocation(lsegm, off, &rel, kind, false);
                }
            }
        }

        Ok(())
    }

    pub fn apply_dynamic_relocations(
        &self,
        lsegm: &mut LoadableSegment<'data>,
    ) -> Result<(), LoaderError> {
        let Some(drels) = self.elf.dynamic_relocations() else {
            return Ok(());
        };

        let offset = lsegm.address().offset();
        let last_offset = lsegm.last_address().offset();

        // TODO: add base address to dynamic relocations offset
        for (off, rel) in drels.filter(|(off, _)| *off >= offset && *off <= last_offset) {
            tracing::trace!("applying dynamic relocation at {}", Address::from(off));

            // Compute offset in the segment
            let off = off - offset;

            match rel.kind() {
                RelocationKind::Unknown => {
                    let RelocationFlags::Elf { r_type } = rel.flags() else {
                        // NOTE: we could probably panic here
                        continue;
                    };

                    match self.elf.architecture() {
                        Architecture::X86_64 => {
                            self.apply_x86_64_relocation(lsegm, off, &rel, r_type, true);
                        }
                        arch => {
                            tracing::warn!(
                                "unsupported architecture {arch:?} for relocation {:?}",
                                rel.kind()
                            );
                        }
                    }
                }
                kind => {
                    self.apply_generic_relocation(lsegm, off, &rel, kind, true);
                }
            }
        }

        Ok(())
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

        if let Some(target) = self.externs.as_ref().and_then(|e| e.get_address(index.0)) {
            tracing::trace!("found external symbol {index:?} at {target:#x}");
            return Some(target.offset());
        }

        if let Some(target) = self.locals.get_address(index.0) {
            tracing::trace!("found local symbol {index:?} at {target:#x}");
            return Some(target.offset());
        }

        // FIXME: in this case, we need to compute the address + our base
        // for object files, this base address will be the beginning of the
        // loaded segment containing it, probably we should save the section
        // map computed in `elf_symbols`?

        let table = if is_dynamic {
            self.elf.dynamic_symbol_table()?
        } else {
            self.elf.symbol_table()?
        };

        let symbol = table.symbol_by_index(index).ok()?;

        Some(symbol.address())
    }

    pub(crate) fn mark_function_symbol(&self, address: impl Into<Address>) {
        let address = address.into();

        tracing::trace!("marking symbol {address} as function");

        if self.externs.as_ref().map_or(false, |externs| {
            externs.update_symbol_properties(address, |props| props | SymbolProperties::FUNCTION)
        }) {
            return;
        }

        self.locals
            .update_symbol_properties(address, |props| props | SymbolProperties::FUNCTION);
    }
}
