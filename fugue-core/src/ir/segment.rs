use std::ops::RangeInclusive;

use bitflags::bitflags;
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::Address;
use crate::lifter::ContextSet;

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SegmentProperties: u8 {
        const NONE          = 0b0000_0000;

        const PERM_READ     = 0b0000_0001;
        const PERM_WRITE    = 0b0000_0010;
        const PERM_EXECUTE  = 0b0000_0100;

        const PERM_ALL      = Self::PERM_READ.bits() | Self::PERM_WRITE.bits() | Self::PERM_EXECUTE.bits();

        const UNINITIALISED = 0b0001_0000;
        const LITTLE_ENDIAN = 0b0010_0000;

        const EXTERNAL      = 0b0100_0000;
    }
}

#[repr(transparent)]
pub struct ArchivedSegmentProperties(u8);
unsafe impl rkyv::Portable for ArchivedSegmentProperties {}
unsafe impl rkyv::traits::NoUndef for ArchivedSegmentProperties {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C>
    for ArchivedSegmentProperties
where
    u8: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { u8::check_bytes(value.cast(), context) }
    }
}

impl rkyv::Archive for SegmentProperties {
    type Archived = ArchivedSegmentProperties;
    type Resolver = ();

    fn resolve(&self, _resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        out.write(ArchivedSegmentProperties(self.bits()));
    }
}

impl<S: rkyv::rancor::Fallible + ?Sized> rkyv::Serialize<S> for SegmentProperties {
    fn serialize(&self, _serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized> rkyv::Deserialize<SegmentProperties, D>
    for ArchivedSegmentProperties
{
    fn deserialize(&self, _deserializer: &mut D) -> Result<SegmentProperties, D::Error> {
        Ok(SegmentProperties::from_bits_truncate(self.0))
    }
}

impl SegmentProperties {
    pub fn is_readable(&self) -> bool {
        self.contains(Self::PERM_READ)
    }

    pub fn is_writable(&self) -> bool {
        self.contains(Self::PERM_WRITE)
    }

    pub fn is_executable(&self) -> bool {
        self.contains(Self::PERM_EXECUTE)
    }

    pub fn is_initialised(&self) -> bool {
        !self.is_uninitialised()
    }

    pub fn is_uninitialised(&self) -> bool {
        self.contains(Self::UNINITIALISED)
    }

    pub fn is_little_endian(&self) -> bool {
        self.contains(Self::LITTLE_ENDIAN)
    }

    pub fn is_external(&self) -> bool {
        self.contains(Self::EXTERNAL)
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ExternFunctionTemplate {
    bytes: SmallVec<[u8; 16]>,
    context: ContextSet,
}

impl<T> From<T> for ExternFunctionTemplate
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl ExternFunctionTemplate {
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        Self::new_with(bytes, ContextSet::default())
    }

    pub fn new_with(bytes: impl AsRef<[u8]>, context: ContextSet) -> Self {
        Self {
            bytes: SmallVec::from_slice(bytes.as_ref()),
            context,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ExternSegment {
    address: Address,
    alignment: usize,
    symbols: usize,
    template: ExternFunctionTemplate,
}

#[derive(Debug, Error)]
pub enum ExternSegmentError {
    #[error("extern address {0} out of bounds")]
    AddressOutOfBounds(Address),
    #[error("extern address {0} is misaligned")]
    AddressMisaligned(Address),
}

impl ExternSegment {
    pub fn new(
        address: impl Into<Address>,
        alignment: usize,
        template: ExternFunctionTemplate,
    ) -> Self {
        Self {
            address: address.into(),
            alignment: alignment.next_power_of_two().max(1),
            symbols: 0,
            template,
        }
    }

    pub fn add_extern(&mut self) -> Option<Address> {
        let addr = self.address() + self.size();
        if addr < self.address() {
            return None;
        }
        self.symbols += 1;
        Some(addr)
    }

    pub fn add_extern_at(&mut self, address: impl Into<Address>) -> Result<(), ExternSegmentError> {
        let address = address.into();
        if address < self.address() {
            return Err(ExternSegmentError::AddressOutOfBounds(address));
        }

        let diff = usize::try_from(address.offset() - self.address().offset())
            .map_err(|_| ExternSegmentError::AddressOutOfBounds(address))?;

        if diff % self.aligned_template_size() != 0 {
            return Err(ExternSegmentError::AddressMisaligned(address));
        }

        let Some(required_symbols) = (diff / self.aligned_template_size()).checked_add(1) else {
            return Err(ExternSegmentError::AddressOutOfBounds(address));
        };

        if required_symbols > self.symbols {
            self.symbols = required_symbols;
        }

        Ok(())
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn last_address(&self) -> Option<Address> {
        (self.symbols != 0).then(|| self.address() + self.size() - 1usize)
    }

    pub fn range(&self) -> Option<std::ops::Range<Address>> {
        self.last_address()
            .map(|last| self.address()..(last + 1usize))
    }

    pub fn range_inclusive(&self) -> Option<RangeInclusive<Address>> {
        self.last_address().map(|last| self.address()..=last)
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    pub fn size(&self) -> usize {
        self.symbols * self.aligned_template_size()
    }

    pub fn symbols(&self) -> usize {
        self.symbols
    }

    pub fn template(&self) -> &ExternFunctionTemplate {
        &self.template
    }

    pub fn aligned_template_size(&self) -> usize {
        let template_size = self.template.len();
        (template_size + self.alignment.wrapping_sub(1)) & !self.alignment.wrapping_sub(1)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Address> {
        let start = self.address();
        let step = self.aligned_template_size();
        (0..self.symbols).map(move |i| start + i * step)
    }

    pub fn len(&self) -> usize {
        self.symbols
    }

    pub fn is_empty(&self) -> bool {
        self.symbols == 0
    }
}
