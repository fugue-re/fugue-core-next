use std::cmp::Ordering;

use byteorder::ByteOrder as _;
pub use byteorder::{ReadBytesExt, WriteBytesExt};
use paste::paste;

use crate::endian::Endian;
use crate::{BE, LE};

pub trait ByteOrder: byteorder::ByteOrder + Send + Sync + 'static {
    const ENDIAN: Endian;
    const NATIVE: bool;

    fn read_i8(buffer: &[u8]) -> i8 {
        if buffer.is_empty() {
            0
        } else {
            buffer[0] as i8
        }
    }

    fn write_i8(buffer: &mut [u8], n: i8) {
        if !buffer.is_empty() {
            buffer[0] = n as u8;
        }
    }

    fn read_u8(buffer: &[u8]) -> u8 {
        if buffer.is_empty() {
            0
        } else {
            buffer[0]
        }
    }

    fn write_u8(buffer: &mut [u8], n: u8) {
        if !buffer.is_empty() {
            buffer[0] = n;
        }
    }

    fn read_isize(buffer: &[u8]) -> isize;
    fn write_isize(buffer: &mut [u8], n: isize);

    fn read_usize(buffer: &[u8]) -> usize;
    fn write_usize(buffer: &mut [u8], n: usize);

    fn subpiece(destination: &mut [u8], source: &[u8], amount: usize);
}

impl ByteOrder for BE {
    const ENDIAN: Endian = Endian::Big;
    const NATIVE: bool = cfg!(target_endian = "big");

    #[cfg(target_pointer_width = "32")]
    fn read_isize(buffer: &[u8]) -> isize {
        Self::read_i32(buffer) as isize
    }

    #[cfg(target_pointer_width = "64")]
    fn read_isize(buffer: &[u8]) -> isize {
        Self::read_i64(buffer) as isize
    }

    #[cfg(target_pointer_width = "32")]
    fn write_isize(buffer: &mut [u8], n: isize) {
        Self::write_i32(buffer, n as i32)
    }

    #[cfg(target_pointer_width = "64")]
    fn write_isize(buffer: &mut [u8], n: isize) {
        Self::write_i64(buffer, n as i64)
    }

    #[cfg(target_pointer_width = "32")]
    fn read_usize(buffer: &[u8]) -> usize {
        Self::read_u32(buffer) as usize
    }

    #[cfg(target_pointer_width = "64")]
    fn read_usize(buffer: &[u8]) -> usize {
        Self::read_u64(buffer) as usize
    }

    #[cfg(target_pointer_width = "32")]
    fn write_usize(buffer: &mut [u8], n: usize) {
        Self::write_u32(buffer, n as u32)
    }

    #[cfg(target_pointer_width = "64")]
    fn write_usize(buffer: &mut [u8], n: usize) {
        Self::write_u64(buffer, n as u64)
    }

    fn subpiece(destination: &mut [u8], source: &[u8], amount: usize) {
        let amount = amount.min(source.len());
        let trimmed = &source[..source.len() - amount];
        match trimmed.len().cmp(&destination.len()) {
            Ordering::Less => {
                destination.copy_from_slice(trimmed);
                for i in destination[trimmed.len()..].iter_mut() {
                    *i = 0;
                }
            }
            Ordering::Equal => {
                destination.copy_from_slice(trimmed);
            }
            Ordering::Greater => {
                destination.copy_from_slice(&trimmed[trimmed.len() - destination.len()..])
            }
        }
    }
}

impl ByteOrder for LE {
    const ENDIAN: Endian = Endian::Little;
    const NATIVE: bool = cfg!(target_endian = "little");

    #[cfg(target_pointer_width = "32")]
    fn read_isize(buffer: &[u8]) -> isize {
        Self::read_i32(buffer) as isize
    }

    #[cfg(target_pointer_width = "64")]
    fn read_isize(buffer: &[u8]) -> isize {
        Self::read_i64(buffer) as isize
    }

    #[cfg(target_pointer_width = "32")]
    fn write_isize(buffer: &mut [u8], n: isize) {
        Self::write_i32(buffer, n as i32)
    }

    #[cfg(target_pointer_width = "64")]
    fn write_isize(buffer: &mut [u8], n: isize) {
        Self::write_i64(buffer, n as i64)
    }

    #[cfg(target_pointer_width = "32")]
    fn read_usize(buffer: &[u8]) -> usize {
        Self::read_u32(buffer) as usize
    }

    #[cfg(target_pointer_width = "64")]
    fn read_usize(buffer: &[u8]) -> usize {
        Self::read_u64(buffer) as usize
    }

    #[cfg(target_pointer_width = "32")]
    fn write_usize(buffer: &mut [u8], n: usize) {
        Self::write_u32(buffer, n as u32)
    }

    #[cfg(target_pointer_width = "64")]
    fn write_usize(buffer: &mut [u8], n: usize) {
        Self::write_u64(buffer, n as u64)
    }

    fn subpiece(destination: &mut [u8], source: &[u8], amount: usize) {
        let amount = amount.min(source.len());
        let trimmed = &source[amount..];
        match trimmed.len().cmp(&destination.len()) {
            Ordering::Less => {
                destination[..trimmed.len()].copy_from_slice(trimmed);
                for i in destination[trimmed.len()..].iter_mut() {
                    *i = 0;
                }
            }
            Ordering::Equal | Ordering::Greater => {
                destination.copy_from_slice(&trimmed[..destination.len()]);
            }
        }
    }
}

pub trait ByteCast: Copy {
    const SIZEOF: usize;
    const SIGNED: bool;

    fn read_bytes<O: ByteOrder>(buffer: &[u8]) -> Self;
    fn write_bytes<O: ByteOrder>(&self, buffer: &mut [u8]);
}

macro_rules! impl_for {
    ($t:ident, $read:ident, $write:ident, $signed:ident) => {
        impl ByteCast for $t {
            const SIZEOF: usize = std::mem::size_of::<$t>();
            const SIGNED: bool = $signed;

            fn read_bytes<O: ByteOrder>(buffer: &[u8]) -> Self {
                O::$read(buffer)
            }

            fn write_bytes<O: ByteOrder>(&self, buffer: &mut [u8]) {
                O::$write(buffer, *self)
            }
        }
    };
}

macro_rules! impls_for {
    ([$($tname:ident),*], $signed:ident) => {
        $(
            paste! {
                impl_for!($tname, [<read_ $tname>], [<write_ $tname>], $signed);
            }
        )*
    };
}

impl ByteCast for bool {
    const SIZEOF: usize = 1;
    const SIGNED: bool = false;

    fn read_bytes<O: ByteOrder>(buffer: &[u8]) -> Self {
        !buffer.is_empty() && buffer[0] != 0
    }

    fn write_bytes<O: ByteOrder>(&self, buffer: &mut [u8]) {
        O::write_u8(buffer, if *self { 1 } else { 0 })
    }
}

impls_for! { [i8, i16, i32, i64, i128, isize], true }
impls_for! { [u8, u16, u32, u64, u128, usize], false }
