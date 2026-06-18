use std::mem::size_of;

use object::FileKind;
use object::endian::LittleEndian as LE;
use object::pe::{
    ImageDosHeader, ImageFileHeader, ImageNtHeaders32, ImageNtHeaders64, ImageSectionHeader,
};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};

use crate::loader::LoaderError;
use crate::types::BytesOrMapping;

const SECTION_HEADER_SIZE_OF_RAW_DATA: usize = 16;
const SECTION_HEADER_POINTER_TO_RAW_DATA: usize = 20;

struct SectionFixup {
    header_offset: usize,
    pointer_to_raw_data: u32,
    size_of_raw_data: u32,
}

pub fn repair(data: BytesOrMapping<'_>) -> Result<Option<BytesOrMapping<'_>>, LoaderError> {
    let Some(fixups) = memory_dump_fixups(data.as_ref())? else {
        return Ok(None);
    };

    let mut data = data.into_copy_on_write()?;
    let bytes = data
        .as_mut()
        .ok_or_else(|| LoaderError::format_with("permissive repair requires a mutable buffer"))?;

    for fixup in fixups {
        let size = fixup.header_offset + SECTION_HEADER_SIZE_OF_RAW_DATA;
        let pointer = fixup.header_offset + SECTION_HEADER_POINTER_TO_RAW_DATA;
        bytes[size..size + 4].copy_from_slice(&fixup.size_of_raw_data.to_le_bytes());
        bytes[pointer..pointer + 4].copy_from_slice(&fixup.pointer_to_raw_data.to_le_bytes());
    }

    Ok(Some(data))
}

fn memory_dump_fixups(data: &[u8]) -> Result<Option<Vec<SectionFixup>>, LoaderError> {
    match FileKind::parse(data).map_err(LoaderError::format)? {
        FileKind::Pe32 => collect_fixups::<ImageNtHeaders32>(data),
        FileKind::Pe64 => collect_fixups::<ImageNtHeaders64>(data),
        _ => Ok(None),
    }
}

fn collect_fixups<Pe>(data: &[u8]) -> Result<Option<Vec<SectionFixup>>, LoaderError>
where
    Pe: ImageNtHeaders,
{
    let dos = ImageDosHeader::parse(data).map_err(LoaderError::format)?;
    let mut offset = dos.nt_headers_offset() as u64;
    let (nt, _) = Pe::parse(data, &mut offset).map_err(LoaderError::format)?;
    let sections = nt.sections(data, offset).map_err(LoaderError::format)?;

    let section_alignment = nt.optional_header().section_alignment() as u64;
    if section_alignment == 0 {
        return Ok(None);
    }

    let size_of_optional_header = nt.file_header().size_of_optional_header.get(LE) as usize;
    let table_offset = dos.nt_headers_offset() as usize
        + size_of::<u32>()
        + size_of::<ImageFileHeader>()
        + size_of_optional_header;

    let len = data.len() as u64;
    let mut virtual_image = 0u64;
    let mut disk_image = 0u64;

    for section in sections.iter() {
        let virtual_size = section.virtual_size.get(LE) as u64;
        let virtual_address = section.virtual_address.get(LE) as u64;
        let size_of_raw_data = section.size_of_raw_data.get(LE) as u64;
        let pointer_to_raw_data = section.pointer_to_raw_data.get(LE) as u64;

        if virtual_size > 0 {
            let end =
                (virtual_address + virtual_size).div_ceil(section_alignment) * section_alignment;
            virtual_image = virtual_image.max(end);
        }

        if size_of_raw_data > 0 {
            disk_image = disk_image.max(pointer_to_raw_data + size_of_raw_data);
        }
    }

    if len < virtual_image || virtual_image <= disk_image {
        return Ok(None);
    }

    let mut fixups = Vec::new();

    for (index, section) in sections.iter().enumerate() {
        let virtual_size = section.virtual_size.get(LE);
        let virtual_address = section.virtual_address.get(LE);

        if virtual_size == 0 || virtual_address as u64 + virtual_size as u64 > len {
            continue;
        }

        fixups.push(SectionFixup {
            header_offset: table_offset + index * size_of::<ImageSectionHeader>(),
            pointer_to_raw_data: virtual_address,
            size_of_raw_data: virtual_size,
        });
    }

    Ok(Some(fixups))
}
