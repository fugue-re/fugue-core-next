use object::read::macho::{MachHeader, MachOFile};
use object::{Object, ObjectSegment, ReadRef};

use crate::ir::RawAddress;
use crate::loader::LoaderError;

pub(crate) fn read_entry<'data, Mach, R>(
    macho: &MachOFile<'data, Mach, R>,
) -> Result<Option<RawAddress>, LoaderError>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    let mut commands = macho.macho_load_commands().map_err(LoaderError::format)?;
    while let Some(command) = commands.next().map_err(LoaderError::format)? {
        let Some(entry) = command.entry_point().map_err(LoaderError::format)? else {
            continue;
        };
        let file_offset = entry.entryoff.get(macho.endian());
        for segment in macho.segments() {
            let (offset, size) = segment.file_range();
            let Some(last) = offset.checked_add(size) else {
                continue;
            };
            if file_offset >= offset && file_offset < last {
                let address = segment
                    .address()
                    .checked_add(file_offset - offset)
                    .ok_or_else(|| LoaderError::address_overflow(segment.address()))?;
                return Ok(Some(RawAddress::from(address)));
            }
        }
        return Err(LoaderError::format_with(
            "Mach-O entry point is outside every segment",
        ));
    }

    let entry = macho.entry();
    Ok((entry != 0).then(|| RawAddress::from(entry)))
}
