use bitflags::bitflags;

use crate::storage::schema::bitflags::archived_bitflags;

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SegmentProperties: u8 {
        const NONE          = 0b0000_0000;

        const PERM_READ     = 0b0000_0001;
        const PERM_WRITE    = 0b0000_0010;
        const PERM_EXECUTE  = 0b0000_0100;

        const PERM_ALL      = Self::PERM_READ.bits() | Self::PERM_WRITE.bits() | Self::PERM_EXECUTE.bits();

        const UNINITIALISED = 0b0001_0000;
        const BIG_ENDIAN    = 0b0010_0000;
    }
}

archived_bitflags!(SegmentProperties, ArchivedSegmentProperties, u8);

impl SegmentProperties {
    pub fn is_readable(&self) -> bool {
        self.contains(Self::PERM_READ)
    }

    pub fn is_writable(&self) -> bool {
        self.contains(Self::PERM_WRITE)
    }

    pub fn is_executable(&self) -> bool {
        self.contains(Self::PERM_EXECUTE)
    }

    pub fn is_initialised(&self) -> bool {
        !self.is_uninitialised()
    }

    pub fn is_uninitialised(&self) -> bool {
        self.contains(Self::UNINITIALISED)
    }

    pub fn is_big_endian(&self) -> bool {
        self.contains(Self::BIG_ENDIAN)
    }
}
