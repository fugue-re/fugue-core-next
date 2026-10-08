use std::marker::PhantomData;
use std::mem::size_of;

use object::elf::{
    DT_GNU_HASH, DT_HASH, DT_JMPREL, DT_PLTREL, DT_PLTRELSZ, DT_REL, DT_RELA, DT_RELASZ, DT_RELSZ,
    DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB, EM_MIPS, FileHeader32, FileHeader64, PT_LOAD,
    SHT_DYNAMIC, SHT_DYNSYM, SHT_REL, SHT_RELA, SHT_STRTAB,
};
use object::read::elf::{Dyn, FileHeader, GnuHashTable, HashTable, ProgramHeader, Rel, Rela};
use object::write::WritableBuffer;
use object::write::elf::{SectionHeader, Writer};
use object::{Endian, Endianness, FileKind, pod};
use thiserror::Error;

use crate::loader::LoaderError;
use crate::loader::elf::read::image::ElfImageData;
use crate::loader::elf::read::mips64;
use crate::types::BytesOrMapping;

#[derive(Debug, Error)]
enum SectionHeaderRepairError {
    #[error("invalid file header")]
    InvalidFileHeader,
}

pub(crate) fn try_repair<'data>(
    data: BytesOrMapping<'data>,
) -> Result<Option<ElfImageData<'data>>, LoaderError> {
    match FileKind::parse(data.as_ref()).map_err(LoaderError::format)? {
        FileKind::Elf32 => try_repair_with::<FileHeader32<Endianness>>(data),
        FileKind::Elf64 => try_repair_with::<FileHeader64<Endianness>>(data),
        _ => {
            tracing::trace!("section header repair is not applicable");
            Ok(None)
        }
    }
}

fn try_repair_with<'data, Elf>(
    data: BytesOrMapping<'data>,
) -> Result<Option<ElfImageData<'data>>, LoaderError>
where
    Elf: SectionHeaderFields<Endian = Endianness>,
{
    if let Some(plan) = DynamicSectionRepairPlan::<Elf>::try_new(&data)? {
        return plan.apply(data).map(Some);
    }
    if let Some(plan) = SectionHeaderRepairPlan::<Elf>::try_new(&data)? {
        return plan.apply(data).map(Some);
    }
    Ok(None)
}

trait SectionHeaderFields: FileHeader {
    fn clear_section_headers(&mut self, endian: Self::Endian);

    fn set_section_headers(&mut self, endian: Self::Endian, shoff: u64, shnum: u16, shstrndx: u16);
}

impl<E: Endian> SectionHeaderFields for FileHeader32<E> {
    fn clear_section_headers(&mut self, endian: E) {
        self.e_shoff.set(endian, 0);
        self.e_shnum.set(endian, 0);
        self.e_shstrndx.set(endian, 0);
    }

    fn set_section_headers(&mut self, endian: E, shoff: u64, shnum: u16, shstrndx: u16) {
        self.e_shoff.set(endian, shoff as u32);
        self.e_shentsize
            .set(endian, size_of::<Self::SectionHeader>() as u16);
        self.e_shnum.set(endian, shnum);
        self.e_shstrndx.set(endian, shstrndx);
    }
}

impl<E: Endian> SectionHeaderFields for FileHeader64<E> {
    fn clear_section_headers(&mut self, endian: E) {
        self.e_shoff.set(endian, 0);
        self.e_shnum.set(endian, 0);
        self.e_shstrndx.set(endian, 0);
    }

    fn set_section_headers(&mut self, endian: E, shoff: u64, shnum: u16, shstrndx: u16) {
        self.e_shoff.set(endian, shoff);
        self.e_shentsize
            .set(endian, size_of::<Self::SectionHeader>() as u16);
        self.e_shnum.set(endian, shnum);
        self.e_shstrndx.set(endian, shstrndx);
    }
}

struct SectionHeaderRepairPlan<Elf>
where
    Elf: SectionHeaderFields,
{
    endian: Elf::Endian,
    _marker: PhantomData<Elf>,
}

impl<Elf> SectionHeaderRepairPlan<Elf>
where
    Elf: SectionHeaderFields,
{
    fn try_new(data: &[u8]) -> Result<Option<Self>, LoaderError> {
        let header = Elf::parse(data).map_err(LoaderError::format)?;
        let endian = header.endian().map_err(LoaderError::format)?;
        header
            .program_headers(endian, data)
            .map_err(LoaderError::format)?;

        if header.sections(endian, data).is_ok() {
            tracing::trace!("section header repair is not applicable");
            return Ok(None);
        }

        Ok(Some(Self {
            endian,
            _marker: PhantomData,
        }))
    }

    fn apply<'data>(self, data: BytesOrMapping<'data>) -> Result<ElfImageData<'data>, LoaderError> {
        let mut data = data.into_copy_on_write()?;
        let bytes = data
            .as_mut()
            .expect("copy-on-write buffer should be available");

        let (header, _) = pod::from_bytes_mut::<Elf>(bytes)
            .map_err(|_| LoaderError::format(SectionHeaderRepairError::InvalidFileHeader))?;

        tracing::warn!("ignoring invalid ELF section headers; loading from program headers");
        header.clear_section_headers(self.endian);

        Ok(ElfImageData::new(data))
    }
}

struct DynamicSectionRepairPlan<Elf>
where
    Elf: SectionHeaderFields<Endian = Endianness>,
{
    endian: Endianness,
    sections: Vec<(&'static [u8], SectionHeader)>,
    _marker: PhantomData<Elf>,
}

impl<Elf> DynamicSectionRepairPlan<Elf>
where
    Elf: SectionHeaderFields<Endian = Endianness>,
{
    fn try_new(data: &[u8]) -> Result<Option<Self>, LoaderError> {
        let header = Elf::parse(data).map_err(LoaderError::format)?;
        let endian = header.endian().map_err(LoaderError::format)?;
        if header
            .sections(endian, data)
            .is_ok_and(|sections| !sections.is_empty())
        {
            return Ok(None);
        }

        let segments = header
            .program_headers(endian, data)
            .map_err(LoaderError::format)?;
        let Some((dynamic_segment, dynamic)) = segments.iter().find_map(|segment| {
            let dynamic = segment.dynamic(endian, data).ok()??;
            Some((segment, dynamic))
        }) else {
            return Ok(None);
        };

        let value = |tag| {
            dynamic
                .iter()
                .find(|entry| entry.tag(endian) == tag)
                .map(|entry| entry.val(endian))
        };
        let offset_of = |address: u64| {
            segments.iter().find_map(|segment| {
                let delta = address.checked_sub(segment.p_vaddr(endian).into())?;
                (segment.p_type(endian) == PT_LOAD
                    && delta < Into::<u64>::into(segment.p_filesz(endian)))
                .then(|| Into::<u64>::into(segment.p_offset(endian)) + delta)
            })
        };
        let section = |sh_type, address, size, sh_entsize| {
            Some(SectionHeader {
                name: None,
                sh_type,
                sh_flags: 0,
                sh_addr: address,
                sh_offset: offset_of(address)?,
                sh_size: size,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize,
            })
        };
        let table = |tag| data.get(usize::try_from(offset_of(value(tag)?)?).ok()?..);
        let relocation = |name, sh_type, address, size| {
            let sh_entsize = if sh_type == SHT_RELA {
                size_of::<Elf::Rela>()
            } else {
                size_of::<Elf::Rel>()
            };
            Some((name, section(sh_type, address, size, sh_entsize as u64)?))
        };

        let mut relocations = Vec::new();
        if let (Some(address), Some(size)) = (value(DT_JMPREL), value(DT_PLTRELSZ)) {
            let (name, sh_type) = if value(DT_PLTREL) == Some(DT_RELA as u64) {
                (&b".rela.plt"[..], SHT_RELA)
            } else {
                (&b".rel.plt"[..], SHT_REL)
            };
            relocations.extend(relocation(name, sh_type, address, size));
        }
        if let (Some(address), Some(size)) = (value(DT_RELA), value(DT_RELASZ)) {
            relocations.extend(relocation(&b".rela.dyn"[..], SHT_RELA, address, size));
        }
        if let (Some(address), Some(size)) = (value(DT_REL), value(DT_RELSZ)) {
            relocations.extend(relocation(&b".rel.dyn"[..], SHT_REL, address, size));
        }

        let mut sections = Vec::new();
        let mut dynstr_index = 0;
        if let Some(dynstr) = value(DT_STRTAB)
            .zip(value(DT_STRSZ))
            .and_then(|(address, size)| section(SHT_STRTAB, address, size, 0))
        {
            sections.push((&b".dynstr"[..], dynstr));
            dynstr_index = sections.len() as u32;

            let syment = value(DT_SYMENT).unwrap_or(size_of::<Elf::Sym>() as u64);
            let symbol_count = table(DT_HASH)
                .and_then(|bytes| HashTable::<Elf>::parse(endian, bytes).ok())
                .map(|table| u64::from(table.symbol_table_length()))
                .or_else(|| {
                    table(DT_GNU_HASH)
                        .and_then(|bytes| GnuHashTable::<Elf>::parse(endian, bytes).ok())
                        .and_then(|table| table.symbol_table_length(endian))
                        .map(u64::from)
                })
                .or_else(|| Self::relocation_symbol_count(header, endian, data, &relocations));

            if let Some(mut dynsym) = value(DT_SYMTAB)
                .zip(symbol_count)
                .and_then(|(address, count)| section(SHT_DYNSYM, address, count * syment, syment))
            {
                dynsym.sh_link = dynstr_index;
                sections.push((&b".dynsym"[..], dynsym));
                let dynsym_index = sections.len() as u32;
                for (_, relocation) in &mut relocations {
                    relocation.sh_link = dynsym_index;
                }
            }
        }

        sections.push((
            &b".dynamic"[..],
            SectionHeader {
                name: None,
                sh_type: SHT_DYNAMIC,
                sh_flags: 0,
                sh_addr: dynamic_segment.p_vaddr(endian).into(),
                sh_offset: dynamic_segment.p_offset(endian).into(),
                sh_size: dynamic_segment.p_filesz(endian).into(),
                sh_link: dynstr_index,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: size_of::<Elf::Dyn>() as u64,
            },
        ));
        sections.extend(relocations);

        Ok(Some(Self {
            endian,
            sections,
            _marker: PhantomData,
        }))
    }

    fn relocation_symbol_count(
        header: &Elf,
        endian: Endianness,
        data: &[u8],
        relocations: &[(&'static [u8], SectionHeader)],
    ) -> Option<u64> {
        relocations
            .iter()
            .filter_map(|(_, section)| {
                let start = usize::try_from(section.sh_offset).ok()?;
                let end = start.checked_add(usize::try_from(section.sh_size).ok()?)?;
                let bytes = data.get(start..end)?;
                if section.sh_type == SHT_RELA {
                    let count = bytes.len() / size_of::<Elf::Rela>();
                    let (entries, _) = pod::slice_from_bytes::<Elf::Rela>(bytes, count).ok()?;
                    entries
                        .iter()
                        .map(|entry| Self::relocation_symbol(header, endian, entry))
                        .max()
                } else {
                    let count = bytes.len() / size_of::<Elf::Rel>();
                    let (entries, _) = pod::slice_from_bytes::<Elf::Rel>(bytes, count).ok()?;
                    entries.iter().map(|entry| entry.r_sym(endian)).max()
                }
            })
            .max()
            .map(|symbol| u64::from(symbol) + 1)
    }

    fn relocation_symbol(header: &Elf, endian: Endianness, relocation: &Elf::Rela) -> u32 {
        match header.e_machine(endian) {
            EM_MIPS if header.is_class_64() => mips64::relocation_symbol::<Elf>(relocation, endian),
            _ => relocation.r_sym(endian, false),
        }
    }

    fn apply<'data>(self, data: BytesOrMapping<'data>) -> Result<ElfImageData<'data>, LoaderError> {
        let shnum = self.sections.len() + 2;
        let mut tail = ElfImageTail {
            offset: data.len(),
            bytes: Vec::new(),
        };

        let mut writer = Writer::new(self.endian, Elf::is_type_64_sized(), &mut tail);
        writer.reserve_until(data.len());
        writer.reserve_null_section_index();
        let names = self
            .sections
            .iter()
            .map(|(name, _)| {
                let name = writer.add_section_name(name);
                writer.reserve_section_index();
                name
            })
            .collect::<Vec<_>>();
        writer.reserve_shstrtab_section_index();
        writer.reserve_shstrtab();
        writer.reserve_section_headers();

        writer.write_shstrtab();
        writer.write_null_section_header();
        for ((_, mut section), name) in self.sections.into_iter().zip(names) {
            section.name = Some(name);
            writer.write_section_header(&section);
        }
        writer.write_shstrtab_section_header();

        let shoff = tail.len() - shnum * size_of::<Elf::SectionHeader>();

        let mut data = data.into_copy_on_write()?;
        let bytes = data
            .as_mut()
            .expect("copy-on-write buffer should be available");
        let (header, _) = pod::from_bytes_mut::<Elf>(bytes)
            .map_err(|_| LoaderError::format(SectionHeaderRepairError::InvalidFileHeader))?;

        tracing::warn!("synthesising ELF section headers from the dynamic segment");
        header.set_section_headers(
            self.endian,
            shoff as u64,
            u16::try_from(shnum).expect("synthesised sections fit in u16"),
            u16::try_from(shnum - 1).expect("synthesised sections fit in u16"),
        );

        Ok(ElfImageData::new_with(data, tail.bytes))
    }
}

struct ElfImageTail {
    offset: usize,
    bytes: Vec<u8>,
}

impl WritableBuffer for ElfImageTail {
    fn len(&self) -> usize {
        self.offset + self.bytes.len()
    }

    fn reserve(&mut self, size: usize) -> Result<(), ()> {
        self.bytes.reserve(size.saturating_sub(self.len()));
        Ok(())
    }

    fn resize(&mut self, new_len: usize) {
        self.bytes.resize(new_len - self.offset, 0);
    }

    fn write_bytes(&mut self, val: &[u8]) {
        self.bytes.extend_from_slice(val);
    }
}
