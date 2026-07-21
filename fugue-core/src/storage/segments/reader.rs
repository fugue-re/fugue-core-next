use crate::ir::{Address, SegmentProperties};
use crate::storage::segments::view::SegmentMappingView;
use crate::storage::segments::{SegmentStorage, SegmentStorageError};

pub struct SegmentReader<'a> {
    segments: &'a SegmentStorage,
    view: Option<SegmentMappingView<'a>>,
}

impl<'a> SegmentReader<'a> {
    pub fn new(segments: &'a SegmentStorage) -> Self {
        Self {
            segments,
            view: None,
        }
    }

    pub fn view(&mut self, address: Address) -> Option<&SegmentMappingView<'a>> {
        let cached = self
            .view
            .as_ref()
            .is_some_and(|view| view.is_valid() && view.contains(address));
        if !cached {
            self.view = self.segments.view_at(address).ok();
        }
        self.view.as_ref().filter(|view| view.contains(address))
    }

    pub fn properties(&mut self, address: Address) -> Option<SegmentProperties> {
        self.view(address).map(SegmentMappingView::properties)
    }

    pub fn read_bytes(
        &mut self,
        address: Address,
        buffer: &mut [u8],
    ) -> Result<usize, SegmentStorageError> {
        match self.view(address) {
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
