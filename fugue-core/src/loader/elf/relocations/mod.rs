use object::read::elf::{ElfFile, ElfSection, FileHeader};
use object::{
    Architecture, Object, ObjectSection, ReadRef, Relocation, RelocationFlags, RelocationKind,
    RelocationTarget,
};

use crate::ir::{Address, SymbolProperties};
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
    base: Address,
    locals: &'file LocalSymbols,
    externs: Option<&'file ExternSymbols>,
    is_object: bool,
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
        is_object: bool,
    ) -> Self {
        Self {
            elf,
            base: Address::zero(),
            locals,
            externs,
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
        let origin_offset = origin.offset();
        let origin_last_offset = origin_offset + lsegm.len() as u64 - 1;

        // NOTE: we account for a new base address when computing the relevant to dynamic relocations
        for (off, rel) in
            drels.filter(|(off, _)| *off >= origin_offset && *off <= origin_last_offset)
        {
            tracing::trace!("applying dynamic relocation at {}", Address::from(off));

            // Compute offset in the segment
            let off = off - origin_offset;

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

        // NOTE: this should only be checked if we are processing dynamic relocations?
        if (is_dynamic || self.is_object)
            && let Some(target) = self.externs.as_ref().and_then(|e| e.get_address(index.0))
        {
            tracing::trace!("found external symbol {index:?} at {target:#x}");
            return Some(target.offset());
        }

        if !is_dynamic && let Some(target) = self.locals.get_address(index.0) {
            tracing::trace!("found local symbol {index:?} at {target:#x}");
            return Some(target.offset());
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
