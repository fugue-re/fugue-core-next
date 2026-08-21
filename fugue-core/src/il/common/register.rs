use std::collections::BTreeMap;
use std::ops::Range;
use std::ptr;
use std::sync::{Arc, LazyLock};

use parking_lot::RwLock;
use rustc_hash::FxHashMap;

use crate::il::common::IlError;
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
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct RegisterId(u64);

impl RegisterId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0
    }
}

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
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct FlagId(u64);

impl FlagId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RegisterRange {
    start: u64,
    end: u64,
}

impl RegisterRange {
    pub fn new(byte_offset: u64, byte_size: usize) -> Result<Self, IlError> {
        let byte_size =
            u64::try_from(byte_size).map_err(|_| IlError::integer_overflow("register range"))?;
        let end = byte_offset
            .checked_add(byte_size)
            .ok_or_else(|| IlError::integer_overflow("register range"))?;

        Ok(Self {
            start: byte_offset,
            end,
        })
    }

    pub const fn byte_offset(&self) -> u64 {
        self.start
    }

    const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub const fn byte_size(&self) -> u64 {
        self.end - self.start
    }

    fn merge(&mut self, other: Self) -> bool {
        if other.start >= self.end {
            return false;
        }
        self.end = self.end.max(other.end);
        true
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RegisterSlice {
    root: RegisterId,
    root_bits: u32,
    byte_offset: u32,
    bits: u32,
}

impl RegisterSlice {
    pub const fn root(self) -> RegisterId {
        self.root
    }

    pub const fn root_bits(self) -> u32 {
        self.root_bits
    }

    pub const fn byte_offset(self) -> u32 {
        self.byte_offset
    }

    pub const fn bits(self) -> u32 {
        self.bits
    }

    pub const fn is_root(self) -> bool {
        self.byte_offset == 0 && self.bits == self.root_bits
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

#[derive(Debug, Clone)]
pub struct RegisterBank {
    language: &'static Language,
    roots: Arc<[RegisterRange]>,
}

static LANGUAGE_RANGES: LazyLock<RwLock<FxHashMap<usize, Arc<[RegisterRange]>>>> =
    LazyLock::new(|| RwLock::new(FxHashMap::default()));

fn normalise_register_ranges(mut roots: Vec<RegisterRange>) -> Arc<[RegisterRange]> {
    roots.retain(|range| !range.is_empty());
    roots.sort_unstable_by_key(|range| (range.start, range.end));

    let mut output = 0usize;
    for input in 0..roots.len() {
        let range = roots[input];
        if output != 0 && roots[output - 1].merge(range) {
            continue;
        }
        roots[output] = range;
        output += 1;
    }
    roots.truncate(output);
    Arc::from(roots)
}

fn language_register_ranges(language: &'static Language) -> Result<Arc<[RegisterRange]>, IlError> {
    let key = ptr::from_ref(language).addr();
    if let Some(ranges) = LANGUAGE_RANGES.read().get(&key) {
        return Ok(ranges.clone());
    }

    let ranges = language
        .registers()
        .filter(|(_, register)| register.size() != 0)
        .map(|(_, register)| RegisterRange::new(register.offset(), register.size()))
        .collect::<Result<Vec<_>, _>>()?;
    let ranges = normalise_register_ranges(ranges);
    LANGUAGE_RANGES.write().insert(key, ranges.clone());

    Ok(ranges)
}

fn preserved_register_roots(slices: impl IntoIterator<Item = RegisterSlice>) -> Vec<RegisterId> {
    let mut roots = BTreeMap::<RegisterId, PreservedRegisterCoverage>::new();
    for slice in slices {
        let start = slice.byte_offset() * 8;
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

impl RegisterBank {
    pub fn new(language: &'static Language) -> Result<Self, IlError> {
        Ok(Self {
            language,
            roots: language_register_ranges(language)?,
        })
    }

    pub const fn language(&self) -> &'static Language {
        self.language
    }

    pub fn insert_ranges(&mut self, ranges: impl IntoIterator<Item = RegisterRange>) {
        let mut roots = self.roots.to_vec();
        roots.extend(ranges);
        self.roots = normalise_register_ranges(roots);
    }

    pub fn root_id(&self, byte_offset: u64, byte_size: usize) -> Option<RegisterId> {
        let byte_size = u64::try_from(byte_size).ok()?;
        let end = byte_offset.checked_add(byte_size)?;
        let index = self.roots.partition_point(|root| root.end <= byte_offset);
        self.roots
            .get(index)
            .filter(|root| root.start <= byte_offset && end <= root.end)
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
            .byte_size()
            .checked_mul(8)
            .and_then(|bits| u32::try_from(bits).ok())
    }

    pub fn slice(&self, range: RegisterRange) -> Result<Option<RegisterSlice>, IlError> {
        let index = self.roots.partition_point(|root| root.end <= range.start);
        let Some(root) = self
            .roots
            .get(index)
            .filter(|root| root.start <= range.start && range.end <= root.end)
        else {
            return Ok(None);
        };
        let offset_bytes = if self.language.is_little_endian() {
            range.start - root.start
        } else {
            root.end - range.end
        };
        let root_bits = root
            .byte_size()
            .checked_mul(8)
            .and_then(|bits| u32::try_from(bits).ok())
            .ok_or_else(|| IlError::integer_overflow("register width"))?;
        let byte_offset = u32::try_from(offset_bytes)
            .map_err(|_| IlError::integer_overflow("register slice offset"))?;
        let bits = range
            .byte_size()
            .checked_mul(8)
            .and_then(|bits| u32::try_from(bits).ok())
            .ok_or_else(|| IlError::integer_overflow("register slice width"))?;

        Ok(Some(RegisterSlice {
            root: RegisterId::new(root.start),
            root_bits,
            byte_offset,
            bits,
        }))
    }

    pub fn call_preserved_registers(&self, compiler: &str) -> Result<Vec<RegisterId>, IlError> {
        let slices = self
            .language
            .call_preserved_registers(compiler)
            .or_else(|| self.language.call_preserved_registers("default"))
            .unwrap_or_default()
            .iter()
            .map(|register| {
                let range = RegisterRange::new(register.offset(), register.size())?;
                Ok(self
                    .slice(range)?
                    .expect("call-preserved register belongs to the language register bank"))
            })
            .collect::<Result<Vec<_>, IlError>>()?;

        Ok(preserved_register_roots(slices))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::lifter::resolve_language;

    fn slice(root: u64, root_bits: u32, byte_offset: u32, bits: u32) -> RegisterSlice {
        RegisterSlice {
            root: RegisterId::new(root),
            root_bits,
            byte_offset,
            bits,
        }
    }

    #[test]
    fn register_slice_offset_follows_endianness() {
        let little_language = resolve_language("x86:LE:64").unwrap();
        let big_language = resolve_language("MIPS:BE:32").unwrap();
        let mut little_bank = RegisterBank::new(little_language).unwrap();
        let mut big_bank = RegisterBank::new(big_language).unwrap();
        let root = RegisterRange::new(0x1_0000, 8).unwrap();
        little_bank.insert_ranges([root]);
        big_bank.insert_ranges([root]);

        let range = RegisterRange::new(0x1_0001, 1).unwrap();
        let little = little_bank.slice(range).unwrap().unwrap();
        let big = big_bank.slice(range).unwrap().unwrap();

        assert_eq!(little.byte_offset(), 1);
        assert_eq!(big.byte_offset(), 6);
        assert_eq!(little.root_bits(), 64);
        assert_eq!(big.root_bits(), 64);
        assert!(ptr::eq(little_bank.language(), little_language));
        assert!(ptr::eq(big_bank.language(), big_language));
    }

    #[test]
    fn preserved_roots_use_compiler_specific_and_default_conventions() {
        let language = resolve_language("x86:LE:64").unwrap();
        let bank = RegisterBank::new(language).unwrap();
        let expected = |compiler| {
            preserved_register_roots(
                language
                    .call_preserved_registers(compiler)
                    .unwrap_or_default()
                    .iter()
                    .map(|register| {
                        bank.slice(RegisterRange::new(register.offset(), register.size()).unwrap())
                            .unwrap()
                            .unwrap()
                    }),
            )
        };

        assert_eq!(
            bank.call_preserved_registers("windows").unwrap(),
            expected("windows")
        );
        assert_eq!(
            bank.call_preserved_registers("missing").unwrap(),
            expected("default")
        );
        assert!(!expected("windows").is_empty());
        assert_ne!(expected("windows"), expected("default"));
    }

    #[test]
    fn preserved_roots_keeps_only_fully_covered_roots() {
        let full = slice(0, 64, 0, 64);
        let halves = [slice(64, 128, 0, 64), slice(64, 128, 8, 64)];
        let partial = slice(256, 512, 0, 128);
        let gapped = [slice(512, 128, 0, 64), slice(512, 128, 12, 32)];

        let roots = preserved_register_roots(
            [full]
                .into_iter()
                .chain(halves)
                .chain([partial])
                .chain(gapped),
        );

        assert_eq!(roots, vec![RegisterId::new(0), RegisterId::new(64)]);
    }

    #[test]
    fn cloned_register_banks_share_roots_until_augmentation() {
        let language = resolve_language("x86:LE:64").unwrap();
        let original = RegisterBank::new(language).unwrap();
        let mut augmented = original.clone();

        assert!(Arc::ptr_eq(&original.roots, &augmented.roots));
        assert!(ptr::eq(original.language(), augmented.language()));

        augmented.insert_ranges([RegisterRange::new(0x1_0000, 8).unwrap()]);

        assert!(!Arc::ptr_eq(&original.roots, &augmented.roots));
        assert_eq!(original.root_bits(RegisterId::new(0x1_0000)), None);
        assert_eq!(augmented.root_bits(RegisterId::new(0x1_0000)), Some(64));
    }
}
