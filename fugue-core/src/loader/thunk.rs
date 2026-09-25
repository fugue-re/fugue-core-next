use std::ops::RangeInclusive;

use thiserror::Error;

use crate::arch::ExternalThunkTemplate;
use crate::ir::RawAddress;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ExternalThunkLayout {
    start: RawAddress,
    alignment: usize,
    thunk_count: usize,
    template: ExternalThunkTemplate,
}

#[derive(Debug, Error)]
pub enum ExternalThunkLayoutError {
    #[error("external thunk address {0} is misaligned")]
    AddressMisaligned(RawAddress),
    #[error("external thunk address {0} is out of bounds")]
    AddressOutOfBounds(RawAddress),
}

impl ExternalThunkLayout {
    pub fn new(
        start: impl Into<RawAddress>,
        alignment: usize,
        template: ExternalThunkTemplate,
    ) -> Self {
        Self {
            start: start.into(),
            alignment: alignment.next_power_of_two().max(1),
            thunk_count: 0,
            template,
        }
    }

    pub fn start(&self) -> RawAddress {
        self.start
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    pub fn thunk_count(&self) -> usize {
        self.thunk_count
    }

    pub fn template(&self) -> &ExternalThunkTemplate {
        &self.template
    }

    pub fn len(&self) -> usize {
        self.thunk_count
    }

    pub fn is_empty(&self) -> bool {
        self.thunk_count == 0
    }

    pub fn range(&self) -> Option<RangeInclusive<RawAddress>> {
        self.last().map(|last| self.start()..=last)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = RawAddress> {
        let start = self.start();
        let step = self.aligned_template_size();
        (0..self.thunk_count).map(move |index| start + index * step)
    }

    pub fn size(&self) -> usize {
        self.thunk_count * self.aligned_template_size()
    }

    pub fn allocate(&mut self) -> Option<RawAddress> {
        let address = self.start() + self.size();
        if address < self.start() {
            return None;
        }
        self.thunk_count += 1;
        Some(address)
    }

    pub fn allocate_at(
        &mut self,
        address: impl Into<RawAddress>,
    ) -> Result<(), ExternalThunkLayoutError> {
        let address = address.into();
        if address < self.start() {
            return Err(ExternalThunkLayoutError::AddressOutOfBounds(address));
        }

        let difference = usize::try_from(address.offset() - self.start().offset())
            .map_err(|_| ExternalThunkLayoutError::AddressOutOfBounds(address))?;

        if difference % self.aligned_template_size() != 0 {
            return Err(ExternalThunkLayoutError::AddressMisaligned(address));
        }

        let Some(required_thunks) = (difference / self.aligned_template_size()).checked_add(1)
        else {
            return Err(ExternalThunkLayoutError::AddressOutOfBounds(address));
        };

        if required_thunks > self.thunk_count {
            self.thunk_count = required_thunks;
        }

        Ok(())
    }

    pub fn last(&self) -> Option<RawAddress> {
        (self.thunk_count != 0).then(|| self.start() + self.size() - 1usize)
    }

    pub fn aligned_template_size(&self) -> usize {
        let template_size = self.template.size();
        (template_size + self.alignment.wrapping_sub(1)) & !self.alignment.wrapping_sub(1)
    }
}
