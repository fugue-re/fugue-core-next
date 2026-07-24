use std::mem;

use fugue_bv::BitVec;
use fugue_bytes::Endian;

use crate::ir::{Address, SegmentProperties};
use crate::storage::segments::provider::SegmentView;
use crate::storage::segments::view::SegmentMappingView;
use crate::storage::segments::{SegmentStorage, SegmentStorageError};

pub struct SegmentMappingCache<'a> {
    segments: &'a SegmentStorage,
    cached_view: Option<SegmentMappingView<'a>>,
    cached_bytes: SegmentView<'a>,
    buffer: Vec<u8>,
}

impl<'a> SegmentMappingCache<'a> {
    pub fn new(segments: &'a SegmentStorage) -> Self {
        Self {
            segments,
            cached_view: None,
            cached_bytes: SegmentView::default(),
            buffer: Vec::new(),
        }
    }

    pub fn view_containing(&mut self, address: Address) -> Option<&SegmentMappingView<'a>> {
        let cached = self
            .cached_view
            .as_ref()
            .is_some_and(|view| view.is_valid() && view.contains(address));
        if !cached {
            self.cached_view = self.segments.view_containing(address).ok();
        }
        self.cached_view
            .as_ref()
            .filter(|view| view.contains(address))
    }

    pub fn segment_properties(&mut self, address: Address) -> Option<SegmentProperties> {
        self.view_containing(address)
            .map(SegmentMappingView::properties)
    }

    pub fn contiguous_bytes_from(
        &mut self,
        address: Address,
    ) -> Result<&[u8], SegmentStorageError> {
        let view = self
            .view_containing(address)
            .ok_or(SegmentStorageError::InvalidAddress)?;
        self.cached_bytes = view
            .bytes_from(address)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        self.cached_bytes
            .as_contiguous()
            .filter(|bytes| !bytes.is_empty())
            .ok_or(SegmentStorageError::InvalidAddressRange)
    }

    pub fn read_bytes(
        &mut self,
        address: Address,
        buffer: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        match self.view_containing(address) {
            Some(view) => view.read_bytes(address, buffer),
            None => Err(SegmentStorageError::InvalidAddress),
        }
    }

    pub fn read_bytes_exact(
        &mut self,
        address: Address,
        buffer: &mut [u8],
    ) -> Result<(), SegmentStorageError> {
        if self.read_bytes(address, buffer)? != buffer.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
    }

    pub fn read_bitvec(
        &mut self,
        address: Address,
        size: usize,
        endian: Endian,
    ) -> Result<BitVec, SegmentStorageError> {
        let mut buffer = mem::take(&mut self.buffer);
        buffer.resize(size, 0);
        let result = self.read_bytes_exact(address, &mut buffer);
        if let Err(error) = result {
            self.buffer = buffer;
            return Err(error);
        }
        let value = match endian {
            Endian::Big => BitVec::from_be_bytes(&buffer),
            Endian::Little => BitVec::from_le_bytes(&buffer),
        };
        self.buffer = buffer;
        Ok(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::SegmentProperties;
    use crate::storage::segments::DEFAULT_SPACE_ID;
    use crate::storage::segments::mapping::SegmentMappingBuilder;
    use crate::storage::segments::provider::InMemorySegmentStorage;

    #[test]
    fn cache_distinguishes_unmapped_addresses_from_backing_gaps() -> Result<(), SegmentStorageError>
    {
        let mut segments = SegmentStorage::empty();
        let provider = segments.open_provider(
            InMemorySegmentStorage::with_size(8),
            SegmentProperties::PERM_ALL,
        );
        segments.write_bytes_direct(provider, 4, &[0x12, 0x34, 0x56, 0x78])?;
        let mapping = segments.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 8, 0, provider).with_name("mapped"),
        )?;
        segments.add_mapping_to_space(DEFAULT_SPACE_ID, mapping)?;

        let mut cache = SegmentMappingCache::new(&segments);
        assert!(matches!(
            cache.contiguous_bytes_from(Address::from(0x2000u64)),
            Err(SegmentStorageError::InvalidAddress)
        ));
        assert!(matches!(
            cache.contiguous_bytes_from(Address::from(0x1000u64)),
            Err(SegmentStorageError::InvalidAddressRange)
        ));
        assert_eq!(
            cache.contiguous_bytes_from(Address::from(0x1004u64))?,
            &[0x12, 0x34, 0x56, 0x78]
        );
        assert_eq!(
            cache
                .read_bitvec(Address::from(0x1004u64), 2, Endian::Big)?
                .to_u64(),
            Some(0x1234)
        );
        assert_eq!(
            cache
                .read_bitvec(Address::from(0x1004u64), 2, Endian::Little)?
                .to_u64(),
            Some(0x3412)
        );

        Ok(())
    }
}
