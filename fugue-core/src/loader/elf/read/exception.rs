use std::mem;

use fallible_iterator::FallibleIterator;
use gimli::{
    BaseAddresses, CieOrFde, EhFrame, EhFrameHdr, EhHdrTable, EndianSlice, RunTimeEndian,
    UnwindSection,
};
use object::{Endian, U32, pod};

use crate::loader::LoaderError;

pub type EhFrameSection<'data> = EhFrame<EndianSlice<'data, RunTimeEndian>>;

pub type EhFrameHdrSection<'data> = EhFrameHdr<EndianSlice<'data, RunTimeEndian>>;

pub type EhFrameHdrTable<'hdr, 'data> = EhHdrTable<'hdr, EndianSlice<'data, RunTimeEndian>>;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ExidxEntry<E: Endian> {
    function: U32<E>,
    data: U32<E>,
}

unsafe impl<E: Endian> pod::Pod for ExidxEntry<E> {}

impl<E: Endian> ExidxEntry<E> {
    pub fn function(&self, endian: E) -> u32 {
        self.function.get(endian)
    }

    pub fn data(&self, endian: E) -> u32 {
        self.data.get(endian)
    }

    pub fn function_address(&self, endian: E, place: u32) -> u32 {
        let offset = ((self.function(endian) << 1) as i32) >> 1;
        place.wrapping_add_signed(offset)
    }

    pub fn parse_table(data: &[u8]) -> Result<&[Self], LoaderError> {
        pod::slice_from_bytes::<Self>(data, data.len() / mem::size_of::<Self>())
            .map(|(entries, _)| entries)
            .map_err(|_| LoaderError::format_with("invalid ARM exception index table"))
    }
}

pub fn eh_frame_functions<'data, 'bases>(
    eh_frame: &EhFrameSection<'data>,
    bases: &'bases BaseAddresses,
) -> impl FallibleIterator<Item = u64, Error = LoaderError> + 'bases
where
    'data: 'bases,
{
    FallibleIterator::filter_map(eh_frame.entries(bases), |entry| match entry {
        CieOrFde::Fde(fde) => fde
            .parse(EhFrameSection::cie_from_offset)
            .map(|fde| Some(fde.initial_address())),
        CieOrFde::Cie(_) => Ok(None),
    })
    .map_err(LoaderError::format)
}

pub fn eh_frame_hdr_functions<'a>(
    table: &'a EhFrameHdrTable<'_, '_>,
    bases: &'a BaseAddresses,
) -> impl FallibleIterator<Item = u64, Error = LoaderError> + 'a {
    FallibleIterator::map(table.iter(bases), |(initial, _)| initial.direct())
        .map_err(LoaderError::format)
}
