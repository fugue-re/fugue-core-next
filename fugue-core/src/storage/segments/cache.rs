use crate::ir::{Address, SegmentProperties};
use crate::storage::segments::provider::SegmentView;
use crate::storage::segments::view::SegmentMappingView;
use crate::storage::segments::{SegmentStorage, SegmentStorageError, SegmentSubMapping};

#[derive(Default)]
pub struct SegmentMappingCache {
    cached: Option<CachedMapping>,
}

struct CachedMapping {
    submapping: SegmentSubMapping,
    generation: u64,
}

impl SegmentMappingCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn view_containing<'a>(
        &mut self,
        segments: &'a SegmentStorage,
        address: Address,
    ) -> Option<SegmentMappingView<'a>> {
        if let Some(cached) = self
            .cached
            .as_ref()
            .filter(|cached| cached.submapping.contains(address))
            && segments.space_generation(address.space()) == Some(cached.generation)
            && let Ok(view) = segments.view_for_submapping(&cached.submapping)
        {
            return Some(view);
        }

        let view = segments.view_containing(address).ok()?;
        self.cached = Some(CachedMapping {
            submapping: SegmentSubMapping::new(
                view.mapping_ref(),
                view.start(),
                view.size(),
                view.properties(),
            ),
            generation: segments.space_generation(address.space()).unwrap_or_default(),
        });
        Some(view)
    }

    pub fn segment_properties(
        &mut self,
        segments: &SegmentStorage,
        address: Address,
    ) -> Option<SegmentProperties> {
        self.view_containing(segments, address)
            .map(|view| view.properties())
    }

    pub fn contiguous_bytes_from<'a>(
        &mut self,
        segments: &'a SegmentStorage,
        address: Address,
    ) -> Result<SegmentView<'a>, SegmentStorageError> {
        let view = self
            .view_containing(segments, address)
            .ok_or(SegmentStorageError::InvalidAddress)?;
        let bytes = view
            .bytes_from(address)
            .ok_or(SegmentStorageError::InvalidAddressRange)?;
        if bytes.as_contiguous().is_some_and(|bytes| !bytes.is_empty()) {
            Ok(bytes)
        } else {
            Err(SegmentStorageError::InvalidAddressRange)
        }
    }

    pub fn read_bytes(
        &mut self,
        segments: &SegmentStorage,
        address: Address,
        buffer: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        match self.view_containing(segments, address) {
            Some(view) => view.read_bytes(address, buffer),
            None => Err(SegmentStorageError::InvalidAddress),
        }
    }

    pub fn read_bytes_exact(
        &mut self,
        segments: &SegmentStorage,
        address: Address,
        buffer: &mut [u8],
    ) -> Result<(), SegmentStorageError> {
        if self.read_bytes(segments, address, buffer)? != buffer.len() {
            return Err(SegmentStorageError::InvalidAddressRange);
        }
        Ok(())
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

        let mut cache = SegmentMappingCache::new();
        assert!(matches!(
            cache.contiguous_bytes_from(&segments, Address::from(0x2000u64)),
            Err(SegmentStorageError::InvalidAddress)
        ));
        assert!(matches!(
            cache.contiguous_bytes_from(&segments, Address::from(0x1000u64)),
            Err(SegmentStorageError::InvalidAddressRange)
        ));
        assert_eq!(
            cache
                .contiguous_bytes_from(&segments, Address::from(0x1004u64))?
                .as_contiguous(),
            Some([0x12, 0x34, 0x56, 0x78].as_slice())
        );
        let mut bytes = [0; 2];
        cache.read_bytes_exact(&segments, Address::from(0x1004u64), &mut bytes)?;
        assert_eq!(bytes, [0x12, 0x34]);

        Ok(())
    }

    #[test]
    fn cache_invalidates_when_a_shadowing_mapping_is_added() -> Result<(), SegmentStorageError> {
        let mut segments = SegmentStorage::empty();
        let lower = segments.open_provider(
            InMemorySegmentStorage::with_size(4),
            SegmentProperties::PERM_ALL,
        );
        segments.write_bytes_direct(lower, 0, &[0xaa, 0xaa, 0xaa, 0xaa])?;
        let lower_mapping = segments.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, lower).with_name("lower"),
        )?;
        segments.add_mapping_to_space(DEFAULT_SPACE_ID, lower_mapping)?;

        let mut cache = SegmentMappingCache::new();
        let mut bytes = [0; 4];
        cache.read_bytes_exact(&segments, Address::from(0x1000u64), &mut bytes)?;
        assert_eq!(bytes, [0xaa, 0xaa, 0xaa, 0xaa]);

        let upper = segments.open_provider(
            InMemorySegmentStorage::with_size(4),
            SegmentProperties::PERM_ALL,
        );
        segments.write_bytes_direct(upper, 0, &[0xbb, 0xbb, 0xbb, 0xbb])?;
        let upper_mapping = segments.create_mapping_from_builder(
            SegmentMappingBuilder::new(0x1000u64, 4, 0, upper).with_name("upper"),
        )?;
        segments.add_mapping_to_space_top(DEFAULT_SPACE_ID, upper_mapping)?;

        cache.read_bytes_exact(&segments, Address::from(0x1000u64), &mut bytes)?;
        assert_eq!(bytes, [0xbb, 0xbb, 0xbb, 0xbb]);

        Ok(())
    }
}
