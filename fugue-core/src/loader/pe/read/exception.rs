use std::mem::size_of;

use object::ReadRef;
use object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION;
use object::pod::{self, Pod};
use object::read::pe::{ImageNtHeaders, PeFile};

use crate::loader::LoaderError;

pub const UNW_FLAG_CHAININFO: u8 = 0x4;

pub fn runtime_functions<'data, Pe, R, Entry>(
    pe: &PeFile<'data, Pe, R>,
) -> Result<&'data [Entry], LoaderError>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
    Entry: Pod,
{
    let Some(directory) = pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
        return Ok(&[]);
    };
    let data = directory
        .data(pe.data(), &pe.section_table())
        .map_err(LoaderError::format)?;
    let (entries, _) = pod::slice_from_bytes::<Entry>(data, data.len() / size_of::<Entry>())
        .map_err(|_| LoaderError::format_with("invalid PE exception directory"))?;
    Ok(entries)
}

pub fn unwind_info_flags<'data, Pe, R>(pe: &PeFile<'data, Pe, R>, address: u32) -> Option<u8>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    let (version_and_flags, _) = pe
        .section_table()
        .pe_data_at(pe.data(), address)?
        .split_first()?;
    Some(version_and_flags >> 3)
}

pub fn is_packed_fragment(unwind_data: u32) -> bool {
    unwind_data & 0b11 == 2
}
