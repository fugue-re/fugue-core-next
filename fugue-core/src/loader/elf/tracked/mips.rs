use object::elf::{DT_PLTGOT, SHT_MIPS_OPTIONS, SHT_MIPS_REGINFO};
use object::read::elf::FileHeader;
use object::{Object, ObjectSymbol, ReadRef};

use super::ElfTrackedSetResolver;
use crate::ir::RawAddress;
use crate::lifter::{TrackedContext, TrackedSet};
use crate::loader::elf::read::mips::{GP_BIAS, OptionsIterator, RegInfo32};

impl<'data, 'file, Elf, R> ElfTrackedSetResolver<'data, 'file, '_, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_mips_tracked_sets(&mut self) {
        let gp = self
            .elf
            .symbol_by_name("_gp")
            .map(|symbol| symbol.address())
            .or_else(|| self.mips_options_gp())
            .or_else(|| self.mips_reginfo_gp())
            .or_else(|| self.dynamic_value(DT_PLTGOT).map(|got| got + GP_BIAS));

        self.apply_mips_gp(gp);
    }

    pub(crate) fn apply_mips_gp(&mut self, gp: Option<u64>) {
        let Some(register) = self.arch.language().register_by_name("gp") else {
            return;
        };
        let Some(gp) = gp else {
            tracing::trace!("no MIPS gp value");
            return;
        };

        let mut tracked = TrackedSet::default();
        tracked.insert(TrackedContext::new(register, self.rebase(gp).offset()));
        self.tracked_sets
            .insert_range(RawAddress::zero()..=RawAddress::MAX, tracked);
    }

    fn mips_options_gp(&self) -> Option<u64> {
        OptionsIterator::<Elf>::new(self.section_data(SHT_MIPS_OPTIONS)?)
            .find_map(|entry| entry.ok()?.reg_info32())?
            .gp(self.elf.endian())
    }

    fn mips_reginfo_gp(&self) -> Option<u64> {
        RegInfo32::<Elf::Endian>::parse(self.section_data(SHT_MIPS_REGINFO)?)?.gp(self.elf.endian())
    }
}
