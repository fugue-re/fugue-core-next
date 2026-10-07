use object::elf::DT_PLTGOT;
use object::read::elf::FileHeader;
use object::{Object, ObjectSection, ReadRef};

use super::ElfTrackedSetResolver;
use crate::ir::RawAddressMap;
use crate::lifter::{TrackedContext, TrackedSet};

const PLT_SECTIONS: [&str; 3] = [".plt", ".plt.got", ".plt.sec"];

impl<'data, 'file, Elf, R> ElfTrackedSetResolver<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
    'file: 'data,
{
    pub(crate) fn apply_x86_tracked_sets(&self, tracked_sets: &mut RawAddressMap<TrackedSet>) {
        let Some(register) = self.arch.language().register_by_name("EBX") else {
            return;
        };

        let Some(got) = self.dynamic_value(DT_PLTGOT).or_else(|| {
            self.elf
                .section_by_name(".got.plt")
                .map(|section| section.address())
        }) else {
            tracing::trace!("no i386 GOT for the PLT");
            return;
        };

        let mut tracked = TrackedSet::default();
        tracked.insert(TrackedContext::new(register, self.rebase(got).offset()));

        for section in PLT_SECTIONS
            .into_iter()
            .filter_map(|name| self.elf.section_by_name(name))
        {
            let start = self.rebase(section.address());
            let Some(last) = section
                .size()
                .checked_sub(1)
                .and_then(|offset| start.checked_add(offset))
            else {
                continue;
            };
            tracked_sets.insert_range(start..=last, tracked.clone());
        }
    }
}
