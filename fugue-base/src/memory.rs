use bincode::{BorrowDecode, Decode, Encode};
use bitflags::bitflags;

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

impl Encode for SegmentProperties {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.bits().encode(encoder)
    }
}

impl<C> Decode<C> for SegmentProperties {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bits = u8::decode(decoder)?;
        Ok(SegmentProperties::from_bits_truncate(bits))
    }
}

impl<'de, C> BorrowDecode<'de, C> for SegmentProperties {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let bits = u8::borrow_decode(decoder)?;
        Ok(SegmentProperties::from_bits_truncate(bits))
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
