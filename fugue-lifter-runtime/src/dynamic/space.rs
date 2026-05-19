use fugue_sleigh_language::spaces::AddressSpace as SleighAddressSpace;

use crate::dynamic::install::Install;
use crate::space::AddressSpaceKind;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct AddressSpace {
    pub(crate) name: Box<str>,
    pub(crate) word_size: usize,
    pub(crate) upper_bound: u64,
    pub(crate) kind: AddressSpaceKind,
}

impl AddressSpace {
    pub(crate) fn from_sleigh(space: &SleighAddressSpace, default_space_id: u8) -> Self {
        Self {
            name: Box::<str>::from(space.name()),
            word_size: space.word_size(),
            upper_bound: space.highest_offset(),
            kind: Self::classify(space, default_space_id),
        }
    }

    fn classify(space: &SleighAddressSpace, default_space_id: u8) -> AddressSpaceKind {
        let id = space.id();
        if id.is_constant() {
            AddressSpaceKind::Constant
        } else if id.is_unique() {
            AddressSpaceKind::Unique
        } else if (space.index() as u8) == default_space_id {
            AddressSpaceKind::Default
        } else {
            AddressSpaceKind::Other
        }
    }
}

impl Install for AddressSpace {
    type Target = crate::space::AddressSpace;

    fn install(self) -> Self::Target {
        let Self {
            name,
            word_size,
            upper_bound,
            kind,
        } = self;
        Self::Target::new(name.install(), word_size, upper_bound, kind)
    }
}
