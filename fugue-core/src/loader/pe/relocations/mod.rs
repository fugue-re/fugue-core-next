use std::collections::BTreeMap;

use object::read::pe::{ImageNtHeaders, PeFile, Relocation};
use object::{Architecture, Object, ReadRef};

use crate::ir::RawAddress;
use crate::loader::pe::extensions::RelocationContext;
use crate::loader::{ImageSegmentContents, LoaderError};

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
    preferred_base: RawAddress,
    current_base: RawAddress,
    import_slots: &'file BTreeMap<RawAddress, RawAddress>,
    base_relocations: &'file [Relocation],
}

impl<'data, 'file, Pe, R> PeSegmentRelocator<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub fn new(
        pe: &'file PeFile<'data, Pe, R>,
        current_base: RawAddress,
        preferred_base: RawAddress,
        import_slots: &'file BTreeMap<RawAddress, RawAddress>,
        base_relocations: &'file [Relocation],
    ) -> Self {
        Self {
            pe,
            preferred_base,
            current_base,
            import_slots,
            base_relocations,
        }
    }

    pub fn apply(&self, bytes: &mut ImageSegmentContents<'data>) -> Result<(), LoaderError> {
        self.apply_base_relocations(bytes)?;
        self.apply_import_slots(bytes)?;
        Ok(())
    }

    pub(crate) fn base_delta_u64(&self) -> u64 {
        (self.current_base - self.preferred_base).offset()
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
        bytes: &mut ImageSegmentContents<'data>,
    ) -> Result<(), LoaderError> {
        if self.current_base == self.preferred_base {
            return Ok(());
        }

        let start = bytes.address().offset();
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| LoaderError::address_overflow(bytes.address()))?;

        for reloc in self.base_relocations {
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
            self.apply_relocation(bytes, offset, reloc.typ)?;
        }

        Ok(())
    }

    fn apply_import_slots(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
    ) -> Result<(), LoaderError> {
        let start = bytes.address();
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| LoaderError::address_overflow(start))?;

        for (slot, target) in self.import_slots.range(start..end) {
            let Some(offset) = bytes.offset_of(*slot) else {
                continue;
            };

            tracing::trace!("patching PE import slot {slot} -> {target}");

            if self.pe.is_64() {
                bytes.write_value(offset, target.offset());
            } else {
                bytes.write_value(offset, target.offset() as u32);
            }
        }

        Ok(())
    }

    fn apply_relocation(
        &self,
        bytes: &mut ImageSegmentContents<'data>,
        offset: u64,
        reloc_type: u16,
    ) -> Result<(), LoaderError> {
        let patch_address = bytes.address() + offset;
        let mut context = RelocationContext::new(
            self.pe,
            self.current_base,
            self.preferred_base,
            patch_address,
            offset,
            reloc_type,
            bytes,
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
