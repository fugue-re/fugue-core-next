use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use parking_lot::RwLock;
use rustc_hash::FxHashMap;

use crate::il::common::{IlArtefact, IlError};
use crate::il::pcode::{PCodeIr, PCodeLocation};
use crate::ir::Endian;
use crate::lifter::Language;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
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

static LANGUAGE_RANGES: LazyLock<RwLock<FxHashMap<usize, Arc<[RegisterRange]>>>> =
    LazyLock::new(|| RwLock::new(FxHashMap::default()));

impl RegisterBank {
    fn language_ranges(language: &'static Language) -> Result<Arc<[RegisterRange]>, IlError> {
        let key = std::ptr::from_ref(language) as usize;
        if let Some(ranges) = LANGUAGE_RANGES.read().get(&key) {
            return Ok(ranges.clone());
        }

        let mut ranges = Vec::new();
        for (_, register) in language.registers() {
            Self::push_range(&mut ranges, register.offset(), register.size())?;
        }
        ranges.sort_unstable_by_key(|range| (range.start, range.end));
        let ranges = Arc::<[RegisterRange]>::from(ranges);
        LANGUAGE_RANGES.write().insert(key, ranges.clone());

        Ok(ranges)
    }

    pub(crate) fn new(language: &'static Language, source: &PCodeIr) -> Result<Self, IlError> {
        let language_ranges = Self::language_ranges(language)?;
        let mut ranges = Vec::new();
        for location in source
            .locations()
            .iter()
            .filter(|location| location.is_register())
        {
            Self::push_range(&mut ranges, location.offset(), usize::from(location.size()))?;
        }
        ranges.sort_unstable_by_key(|range| (range.start, range.end));

        let mut roots = Vec::<RegisterRange>::with_capacity(language_ranges.len());
        let mut merge = |range: RegisterRange| {
            if let Some(root) = roots.last_mut()
                && range.start < root.end
            {
                root.end = root.end.max(range.end);
            } else {
                roots.push(range);
            }
        };

        let mut base = language_ranges.iter().copied().peekable();
        let mut local = ranges.into_iter().peekable();
        loop {
            let next = match (base.peek(), local.peek()) {
                (Some(left), Some(right)) if left.start <= right.start => base.next(),
                (Some(_), Some(_)) => local.next(),
                (Some(_), None) => base.next(),
                (None, Some(_)) => local.next(),
                (None, None) => break,
            };
            if let Some(range) = next {
                merge(range);
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
            .ok_or_else(|| IlError::integer_overflow("register slice"))?;
        let index = self.roots.partition_point(|root| root.end <= start);
        let root = self
            .roots
            .get(index)
            .filter(|root| root.start <= start && end <= root.end)
            .ok_or_else(|| IlError::missing_component(PCodeIr::FORM, "register root"))?;
        let root_bytes = root.end - root.start;
        let offset_bytes = match endian {
            Endian::Little => start - root.start,
            Endian::Big => root.end - end,
        };
        let root_bits = root_bytes
            .checked_mul(8)
            .and_then(|bits| u32::try_from(bits).ok())
            .ok_or_else(|| IlError::integer_overflow("register width"))?;
        let offset = u32::try_from(offset_bytes)
            .map_err(|_| IlError::integer_overflow("register slice offset"))?;

        Ok(RegisterSlice {
            root: RegisterId::new(root.start),
            root_bits,
            offset,
            bits: location.bits(),
        })
    }

    pub(crate) fn call_preserved_registers(
        &self,
        language: &'static Language,
        endian: Endian,
        compiler: &str,
    ) -> Result<Vec<RegisterId>, IlError> {
        let slices = language
            .call_preserved_registers(compiler)
            .or_else(|| language.call_preserved_registers("default"))
            .unwrap_or_default()
            .iter()
            .map(|register| self.slice(&PCodeLocation::from_varnode(language, register), endian))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self::preserved_roots(slices))
    }

    fn preserved_roots(slices: impl IntoIterator<Item = RegisterSlice>) -> Vec<RegisterId> {
        let mut roots: BTreeMap<RegisterId, (u32, Vec<(u32, u32)>)> = BTreeMap::new();
        for slice in slices {
            let start = slice.offset() * 8;
            let entry = roots
                .entry(slice.root())
                .or_insert_with(|| (slice.root_bits(), Vec::new()));
            entry.1.push((start, start + slice.bits()));
        }

        roots
            .into_iter()
            .filter_map(|(root, (root_bits, mut ranges))| {
                ranges.sort_unstable();
                let mut covered = 0;
                for (start, end) in ranges {
                    if start > covered {
                        return None;
                    }
                    covered = covered.max(end);
                }
                (covered >= root_bits).then_some(root)
            })
            .collect()
    }

    fn push_range(ranges: &mut Vec<RegisterRange>, start: u64, size: usize) -> Result<(), IlError> {
        if size == 0 {
            return Ok(());
        }
        let size = u64::try_from(size).map_err(|_| IlError::integer_overflow("register range"))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| IlError::integer_overflow("register range"))?;
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

    fn slice(root: u64, root_bits: u32, offset: u32, bits: u32) -> RegisterSlice {
        RegisterSlice {
            root: RegisterId::new(root),
            root_bits,
            offset,
            bits,
        }
    }

    #[test]
    fn preserved_roots_keeps_only_fully_covered_roots() {
        let full = slice(0, 64, 0, 64);
        let halves = [slice(64, 128, 0, 64), slice(64, 128, 8, 64)];
        let partial = slice(256, 512, 0, 128);
        let gapped = [slice(512, 128, 0, 64), slice(512, 128, 12, 32)];

        let roots = RegisterBank::preserved_roots(
            [full]
                .into_iter()
                .chain(halves)
                .chain([partial])
                .chain(gapped),
        );

        assert_eq!(roots, vec![RegisterId::new(0), RegisterId::new(64)]);
    }
}
