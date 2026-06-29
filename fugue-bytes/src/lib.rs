pub use byteorder::{BE, LE};

pub mod endian;
pub use endian::Endian;

pub mod traits;
pub use traits::{ByteCast, ByteOrder};
