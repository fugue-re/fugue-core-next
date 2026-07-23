use crate::ir::{Address, SegmentProperties};
use crate::storage::segments::view::SegmentMappingView;
use crate::storage::segments::{SegmentStorage, SegmentStorageError};

pub struct SegmentMappingCache<'a> {
    segments: &'a SegmentStorage,
    cached_view: Option<SegmentMappingView<'a>>,
}

impl<'a> SegmentMappingCache<'a> {
    pub fn new(segments: &'a SegmentStorage) -> Self {
        Self {
            segments,
            cached_view: None,
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

    pub fn properties_at(&mut self, address: Address) -> Option<SegmentProperties> {
        self.view_containing(address)
            .map(SegmentMappingView::properties)
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
}
