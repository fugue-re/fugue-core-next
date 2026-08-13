use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{Arc, LazyLock};

use parking_lot::RwLock;
use rustc_hash::FxHashMap;

use crate::il::common::{IlArtefact, IlError, RegisterId};
use crate::il::pcode::{PCodeIr, PCodeLocation};
use crate::ir::Endian;
use crate::lifter::Language;

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

struct PreservedRegisterCoverage {
    root_bits: u32,
    preserved_bits: Vec<Range<u32>>,
}

impl PreservedRegisterCoverage {
    fn new(root_bits: u32) -> Self {
        Self {
            root_bits,
            preserved_bits: Vec::new(),
        }
    }

    fn insert(&mut self, range: Range<u32>) {
        self.preserved_bits.push(range);
    }

    fn merge(&mut self) {
        self.preserved_bits
            .sort_unstable_by_key(|range| (range.start, range.end));

        let mut output = 0usize;
        for input in 0..self.preserved_bits.len() {
            let range = self.preserved_bits[input].clone();
            if output != 0 && range.start <= self.preserved_bits[output - 1].end {
                self.preserved_bits[output - 1].end =
                    self.preserved_bits[output - 1].end.max(range.end);
            } else {
                self.preserved_bits[output] = range;
                output += 1;
            }
        }
        self.preserved_bits.truncate(output);
    }

    fn covers_root(mut self) -> bool {
        self.merge();
        matches!(self.preserved_bits.as_slice(), [range] if range.start == 0 && range.end >= self.root_bits)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct RegisterRange {
    start: u64,
    end: u64,
}

impl RegisterRange {
    fn new(start: u64, size: usize) -> Result<Option<Self>, IlError> {
        if size == 0 {
            return Ok(None);
        }
        let size = u64::try_from(size).map_err(|_| IlError::integer_overflow("register range"))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| IlError::integer_overflow("register range"))?;
        Ok(Some(Self { start, end }))
    }

    fn merge(&mut self, other: Self) -> bool {
        if other.start >= self.end {
            return false;
        }
        self.end = self.end.max(other.end);
        true
    }
}

#[derive(Debug, Clone, Default)]
pub struct RegisterBank {
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
            ranges.extend(RegisterRange::new(register.offset(), register.size())?);
        }
        ranges.sort_unstable_by_key(|range| (range.start, range.end));
        let ranges = Arc::<[RegisterRange]>::from(ranges);
        LANGUAGE_RANGES.write().insert(key, ranges.clone());

        Ok(ranges)
    }

    pub fn new(language: &'static Language) -> Result<Self, IlError> {
        let language_ranges = Self::language_ranges(language)?;
        let mut roots = Vec::<RegisterRange>::with_capacity(language_ranges.len());
        for range in language_ranges.iter().copied() {
            if roots.last_mut().is_none_or(|root| !root.merge(range)) {
                roots.push(range);
            }
        }

        Ok(Self { roots })
    }

    pub(crate) fn for_pcode(
        language: &'static Language,
        source: &PCodeIr,
    ) -> Result<Self, IlError> {
        let language_ranges = Self::language_ranges(language)?;
        let mut ranges = Vec::new();
        for location in source
            .locations()
            .iter()
            .filter(|location| location.is_register())
        {
            ranges.extend(RegisterRange::new(
                location.offset(),
                usize::from(location.size()),
            )?);
        }
        ranges.sort_unstable_by_key(|range| (range.start, range.end));

        let mut roots = Vec::<RegisterRange>::with_capacity(language_ranges.len());
        let mut merge = |range: RegisterRange| {
            if roots.last_mut().is_none_or(|root| !root.merge(range)) {
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

    pub fn root_id(&self, offset: u64, size: usize) -> Option<RegisterId> {
        let size = u64::try_from(size).ok()?;
        let end = offset.checked_add(size)?;
        let index = self.roots.partition_point(|root| root.end <= offset);
        self.roots
            .get(index)
            .filter(|root| root.start <= offset && end <= root.end)
            .map(|root| RegisterId::new(root.start))
    }

    pub fn root_bits(&self, root: RegisterId) -> Option<u32> {
        let index = self
            .roots
            .partition_point(|range| range.start < root.value());
        let range = self
            .roots
            .get(index)
            .filter(|range| range.start == root.value())?;
        range
            .end
            .checked_sub(range.start)
            .and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bits| u32::try_from(bits).ok())
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

    pub fn call_preserved_registers(
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
        let mut roots = BTreeMap::<RegisterId, PreservedRegisterCoverage>::new();
        for slice in slices {
            let start = slice.offset() * 8;
            let coverage = roots
                .entry(slice.root())
                .or_insert_with(|| PreservedRegisterCoverage::new(slice.root_bits()));
            coverage.insert(start..start + slice.bits());
        }

        roots
            .into_iter()
            .filter_map(|(root, coverage)| coverage.covers_root().then_some(root))
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::pcode::{LifterSpaceHandle, PCodeLocationProperties};

    fn slice(root: u64, root_bits: u32, offset: u32, bits: u32) -> RegisterSlice {
        RegisterSlice {
            root: RegisterId::new(root),
            root_bits,
            offset,
            bits,
        }
    }

    #[test]
    fn register_slice_offset_follows_endianness() {
        let bank = RegisterBank {
            roots: vec![RegisterRange::new(0, 8).unwrap().unwrap()],
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
