use std::marker::PhantomData;
use std::mem::size_of;

use object::elf::ODK_REGINFO;
use object::read::Bytes;
use object::read::elf::FileHeader;
use object::{Endian, I32, I64, U16, U32, pod};

use crate::loader::LoaderError;

pub const GP_BIAS: u64 = 0x7ff0;

pub const STO_MIPS_ISA: u8 = 0xc0;
pub const STO_MIPS16: u8 = 0xf0;
pub const STO_MICROMIPS: u8 = 0x80;

pub fn is_compressed(st_other: u8) -> bool {
    st_other & STO_MIPS16 == STO_MIPS16 || st_other & STO_MIPS_ISA == STO_MICROMIPS
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RegInfo32<E: Endian> {
    ri_gprmask: U32<E>,
    ri_cprmask: [U32<E>; 4],
    ri_gp_value: I32<E>,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RegInfo64<E: Endian> {
    ri_gprmask: U32<E>,
    ri_pad: U32<E>,
    ri_cprmask: [U32<E>; 4],
    ri_gp_value: I64<E>,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Options<E: Endian> {
    kind: u8,
    size: u8,
    section: U16<E>,
    info: U32<E>,
}

// SAFETY: each struct is `repr(C)` and built only from `u8` and unaligned byte-array integers,
// so it has no padding and every bit pattern is a valid value.
unsafe impl<E: Endian> pod::Pod for RegInfo32<E> {}
unsafe impl<E: Endian> pod::Pod for RegInfo64<E> {}
unsafe impl<E: Endian> pod::Pod for Options<E> {}

impl<E: Endian> RegInfo32<E> {
    pub fn parse(data: &[u8]) -> Option<&Self> {
        pod::from_bytes::<Self>(data)
            .ok()
            .map(|(reginfo, _)| reginfo)
    }

    pub fn ri_gprmask(&self, endian: E) -> u32 {
        self.ri_gprmask.get(endian)
    }

    pub fn ri_cprmask(&self, endian: E) -> [u32; 4] {
        self.ri_cprmask.map(|mask| mask.get(endian))
    }

    pub fn ri_gp_value(&self, endian: E) -> i32 {
        self.ri_gp_value.get(endian)
    }

    pub fn gp(&self, endian: E) -> Option<u64> {
        let gp = u64::from(self.ri_gp_value(endian).cast_unsigned());
        (gp != 0).then_some(gp)
    }
}

impl<E: Endian> RegInfo64<E> {
    pub fn parse(data: &[u8]) -> Option<&Self> {
        pod::from_bytes::<Self>(data)
            .ok()
            .map(|(reginfo, _)| reginfo)
    }

    pub fn ri_gprmask(&self, endian: E) -> u32 {
        self.ri_gprmask.get(endian)
    }

    pub fn ri_pad(&self, endian: E) -> u32 {
        self.ri_pad.get(endian)
    }

    pub fn ri_cprmask(&self, endian: E) -> [u32; 4] {
        self.ri_cprmask.map(|mask| mask.get(endian))
    }

    pub fn ri_gp_value(&self, endian: E) -> i64 {
        self.ri_gp_value.get(endian)
    }

    pub fn gp(&self, endian: E) -> Option<u64> {
        let gp = self.ri_gp_value(endian).cast_unsigned();
        (gp != 0).then_some(gp)
    }
}

impl<E: Endian> Options<E> {
    pub fn kind(&self) -> u8 {
        self.kind
    }

    pub fn size(&self) -> u8 {
        self.size
    }

    pub fn section(&self, endian: E) -> u16 {
        self.section.get(endian)
    }

    pub fn info(&self, endian: E) -> u32 {
        self.info.get(endian)
    }
}

pub struct OptionsIterator<'data, Elf>
where
    Elf: FileHeader,
{
    data: Bytes<'data>,
    _marker: PhantomData<Elf>,
}

impl<'data, Elf> OptionsIterator<'data, Elf>
where
    Elf: FileHeader,
{
    pub fn new(data: &'data [u8]) -> Self {
        Self {
            data: Bytes(data),
            _marker: PhantomData,
        }
    }

    pub fn next(&mut self) -> Result<Option<OptionsEntry<'data, Elf>>, LoaderError> {
        if self.data.is_empty() {
            return Ok(None);
        }

        let result = self.parse().map(Some);
        if result.is_err() {
            self.data = Bytes(&[]);
        }
        result
    }

    fn parse(&mut self) -> Result<OptionsEntry<'data, Elf>, LoaderError> {
        let header = self
            .data
            .read_at::<Options<Elf::Endian>>(0)
            .map_err(|_| LoaderError::format_with("MIPS options entry is too short"))?;
        let size = usize::from(header.size());
        let payload = size
            .checked_sub(size_of::<Options<Elf::Endian>>())
            .and_then(|length| {
                self.data
                    .read_bytes_at(size_of::<Options<Elf::Endian>>(), length)
                    .ok()
            })
            .ok_or_else(|| LoaderError::format_with("invalid MIPS options entry size"))?
            .0;

        if self.data.skip(size).is_err() {
            self.data = Bytes(&[]);
        }

        Ok(OptionsEntry { header, payload })
    }
}

impl<'data, Elf> Iterator for OptionsIterator<'data, Elf>
where
    Elf: FileHeader,
{
    type Item = Result<OptionsEntry<'data, Elf>, LoaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next().transpose()
    }
}

pub struct OptionsEntry<'data, Elf>
where
    Elf: FileHeader,
{
    header: &'data Options<Elf::Endian>,
    payload: &'data [u8],
}

impl<'data, Elf> OptionsEntry<'data, Elf>
where
    Elf: FileHeader,
{
    pub fn header(&self) -> &'data Options<Elf::Endian> {
        self.header
    }

    pub fn payload(&self) -> &'data [u8] {
        self.payload
    }

    pub fn reg_info32(&self) -> Option<&'data RegInfo32<Elf::Endian>> {
        self.is_reg_info().then(|| RegInfo32::parse(self.payload))?
    }

    pub fn reg_info64(&self) -> Option<&'data RegInfo64<Elf::Endian>> {
        self.is_reg_info().then(|| RegInfo64::parse(self.payload))?
    }

    fn is_reg_info(&self) -> bool {
        u32::from(self.header.kind()) == ODK_REGINFO
    }
}
