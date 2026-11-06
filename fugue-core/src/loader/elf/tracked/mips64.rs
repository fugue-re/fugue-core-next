use object::elf::{DT_PLTGOT, SHT_MIPS_OPTIONS};
use object::read::elf::FileHeader;
use object::{Object, ObjectSymbol, ReadRef};

use super::ElfTrackedSetResolver;
use crate::loader::elf::read::mips::{GP_BIAS, OptionsIterator};

impl<'data, 'file, Elf, R> ElfTrackedSetResolver<'data, 'file, '_, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_mips64_tracked_sets(&mut self) {
        let gp = self
            .elf
            .symbol_by_name("_gp")
            .map(|symbol| symbol.address())
            .or_else(|| self.mips64_options_gp())
            .or_else(|| self.dynamic_value(DT_PLTGOT).map(|got| got + GP_BIAS));

        self.apply_mips_gp(gp);
    }

    fn mips64_options_gp(&self) -> Option<u64> {
        OptionsIterator::<Elf>::new(self.section_data(SHT_MIPS_OPTIONS)?)
            .find_map(|entry| entry.ok()?.reg_info64())?
            .gp(self.elf.endian())
    }
}
