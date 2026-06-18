use std::collections::BTreeMap;

use object::read::pe::{ImageNtHeaders, PeFile};
use object::{Architecture, Object, ReadRef};

use crate::ir::Address;
use crate::loader::pe::extensions::RelocationContext;
use crate::loader::{LoadableSegment, LoaderError};

pub mod generic;

pub mod aarch64;
pub mod arm;
pub mod x86;
pub mod x86_64;

pub struct PeSegmentRelocator<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pe: &'file PeFile<'data, Pe, R>,
    preferred_base: u64,
    current_base: Address,
    import_slots: &'file BTreeMap<Address, Address>,
}

impl<'data, 'file, Pe, R> PeSegmentRelocator<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub fn new(
        pe: &'file PeFile<'data, Pe, R>,
        preferred_base: u64,
        current_base: Address,
        import_slots: &'file BTreeMap<Address, Address>,
    ) -> Self {
        Self {
            pe,
            preferred_base,
            current_base,
            import_slots,
        }
    }

    pub fn apply(&self, lsegm: &mut LoadableSegment<'data>) -> Result<(), LoaderError> {
        self.apply_base_relocations(lsegm)?;
        self.apply_import_slots(lsegm)?;
        Ok(())
    }

    pub(crate) fn base_delta_u64(&self) -> u64 {
        self.current_base.offset().wrapping_sub(self.preferred_base)
    }

    pub(crate) fn base_delta_u32(&self) -> u32 {
        self.base_delta_u64() as u32
    }

    pub(crate) fn base_delta_high(&self) -> u16 {
        (self.base_delta_u64() >> 16) as u16
    }

    pub(crate) fn base_delta_low(&self) -> u16 {
        self.base_delta_u64() as u16
    }

    fn apply_base_relocations(
        &self,
        lsegm: &mut LoadableSegment<'data>,
    ) -> Result<(), LoaderError> {
        if self.current_base.offset() == self.preferred_base {
            return Ok(());
        }

        let Some(mut blocks) = self
            .pe
            .data_directories()
            .relocation_blocks(self.pe.data(), &self.pe.section_table())
            .map_err(LoaderError::format)?
        else {
            return Ok(());
        };

        let start = lsegm.address().offset();
        let end = start
            .checked_add(lsegm.len() as u64)
            .ok_or_else(|| LoaderError::address_overflow(lsegm.address()))?;

        while let Some(block) = blocks.next().map_err(LoaderError::format)? {
            for reloc in block {
                let address = self
                    .current_base
                    .offset()
                    .wrapping_add(reloc.virtual_address as u64);
                if address < start || address >= end {
                    continue;
                }

                let Some(offset) = address.checked_sub(start) else {
                    continue;
                };
                self.apply_relocation(lsegm, offset as usize, reloc.typ)?;
            }
        }

        Ok(())
    }

    fn apply_import_slots(&self, lsegm: &mut LoadableSegment<'data>) -> Result<(), LoaderError> {
        let start = lsegm.address();
        let end = start
            .checked_add(lsegm.len() as u64)
            .ok_or_else(|| LoaderError::address_overflow(start))?;

        for (slot, target) in self.import_slots.range(start..end) {
            let Some(offset) = lsegm.offset_of(*slot) else {
                continue;
            };

            tracing::trace!("patching PE import slot {slot} -> {target}");

            if self.pe.is_64() {
                lsegm.write_value(offset, target.offset());
            } else {
                lsegm.write_value(offset, target.offset() as u32);
            }
        }

        Ok(())
    }

    fn apply_relocation(
        &self,
        lsegm: &mut LoadableSegment<'data>,
        offset: usize,
        reloc_type: u16,
    ) -> Result<(), LoaderError> {
        let patch_address = lsegm.address() + offset;
        let mut context = RelocationContext::new(
            self.pe,
            self.current_base,
            Address::new(self.current_base.space(), self.preferred_base),
            patch_address,
            offset,
            reloc_type,
            lsegm,
        );

        if context.apply_relocation()? {
            return Ok(());
        }

        match self.pe.architecture() {
            Architecture::Aarch64 => {
                self.apply_aarch64_relocation(context.segment_mut(), offset, reloc_type)
            }
            Architecture::Arm => {
                self.apply_arm_relocation(context.segment_mut(), offset, reloc_type)
            }
            Architecture::I386 => {
                self.apply_x86_relocation(context.segment_mut(), offset, reloc_type)
            }
            Architecture::X86_64 => {
                self.apply_x86_64_relocation(context.segment_mut(), offset, reloc_type)
            }
            arch => tracing::warn!(
                "unsupported PE architecture {arch:?} for relocation type {reloc_type:#x}"
            ),
        }

        Ok(())
    }
}
