use crate::il::common::{IlError, IlLevel};
use crate::il::pcode::{PCodeIr, PCodeLocation};
use crate::ir::Endian;
use crate::lifter::Language;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RegisterId(u64);

impl RegisterId {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FlagId(u64);

impl FlagId {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct RegisterSlice {
    root: RegisterId,
    root_bits: u32,
    offset: u32,
    bits: u32,
}

impl RegisterSlice {
    pub(crate) const fn root(self) -> RegisterId {
        self.root
    }

    pub(crate) const fn root_bits(self) -> u32 {
        self.root_bits
    }

    pub(crate) const fn offset(self) -> u32 {
        self.offset
    }

    pub(crate) const fn bits(self) -> u32 {
        self.bits
    }

    pub(crate) const fn is_root(self) -> bool {
        self.offset == 0 && self.bits == self.root_bits
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct RegisterRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RegisterBank {
    roots: Vec<RegisterRange>,
}

impl RegisterBank {
    pub(crate) fn new(language: &'static Language, source: &PCodeIr) -> Result<Self, IlError> {
        let mut ranges = Vec::new();
        for (_, register) in language.registers() {
            Self::push_range(&mut ranges, register.offset(), register.size())?;
        }
        for location in source
            .locations()
            .iter()
            .filter(|location| location.is_register())
        {
            Self::push_range(&mut ranges, location.offset(), usize::from(location.size()))?;
        }
        ranges.sort_unstable_by_key(|range| (range.start, range.end));

        let mut roots = Vec::<RegisterRange>::new();
        for range in ranges {
            if let Some(root) = roots.last_mut()
                && range.start < root.end
            {
                root.end = root.end.max(range.end);
            } else {
                roots.push(range);
            }
        }

        Ok(Self { roots })
    }

    pub(crate) fn slice(
        &self,
        location: &PCodeLocation,
        endian: Endian,
    ) -> Result<RegisterSlice, IlError> {
        let start = location.offset();
        let end = start
            .checked_add(u64::from(location.size()))
            .ok_or(IlError::integer_overflow("register slice"))?;
        let index = self.roots.partition_point(|root| root.end <= start);
        let root = self
            .roots
            .get(index)
            .filter(|root| root.start <= start && end <= root.end)
            .ok_or(IlError::missing_component(IlLevel::PCode, "register root"))?;
        let root_bytes = root.end - root.start;
        let offset_bytes = match endian {
            Endian::Little => start - root.start,
            Endian::Big => root.end - end,
        };
        let root_bits = root_bytes
            .checked_mul(8)
            .and_then(|bits| u32::try_from(bits).ok())
            .ok_or(IlError::integer_overflow("register width"))?;
        let offset = u32::try_from(offset_bytes)
            .map_err(|_| IlError::integer_overflow("register slice offset"))?;

        Ok(RegisterSlice {
            root: RegisterId::new(root.start),
            root_bits,
            offset,
            bits: u32::from(location.size()) * 8,
        })
    }

    fn push_range(ranges: &mut Vec<RegisterRange>, start: u64, size: usize) -> Result<(), IlError> {
        if size == 0 {
            return Ok(());
        }
        let size = u64::try_from(size).map_err(|_| IlError::integer_overflow("register range"))?;
        let end = start
            .checked_add(size)
            .ok_or(IlError::integer_overflow("register range"))?;
        ranges.push(RegisterRange { start, end });
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::pcode::{LifterSpaceHandle, PCodeLocationProperties};

    #[test]
    fn register_slice_offset_follows_endianness() {
        let bank = RegisterBank {
            roots: vec![RegisterRange { start: 0, end: 8 }],
        };
        let location = PCodeLocation::new(
            LifterSpaceHandle::new(1),
            1,
            1,
            PCodeLocationProperties::REGISTER,
        );

        let little = bank.slice(&location, Endian::Little).unwrap();
        let big = bank.slice(&location, Endian::Big).unwrap();

        assert_eq!(little.offset(), 1);
        assert_eq!(big.offset(), 6);
        assert_eq!(little.root_bits(), 64);
        assert_eq!(big.root_bits(), 64);
    }
}
