// SPDX-License-Identifier: Apache-2.0

//! Helpful primitives for developing the crate.

// pub mod array;
pub mod cached_chain;
pub(crate) mod hexline;
mod impl_const_id;
pub mod parser_helper;

use std::{
    io::{Read, Result, Write},
    mem::{size_of, MaybeUninit},
    slice::{from_raw_parts, from_raw_parts_mut},
};

/// A type for which every initialized bit pattern of `size_of::<Self>()` bytes
/// is a valid value.
///
/// # Safety
///
/// Implement this only for types whose fields, recursively, are all integers,
/// arrays, or unions of such types. Types that contain `bool`, `char`, enums,
/// references, pointers, or `NonZero*` values must not implement it.
pub unsafe trait AnyBitPattern: Copy {
    /// Returns a value with every byte set to zero.
    fn zeroed() -> Self {
        // SAFETY: Self accepts every bit pattern, including all zeroes.
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

// SAFETY: Every bit pattern is a valid u32.
unsafe impl AnyBitPattern for u32 {}

// SAFETY: An array is valid when each element is valid.
unsafe impl<T: AnyBitPattern, const N: usize> AnyBitPattern for [T; N] {}

pub trait TypeLoad: Read {
    fn load<T: AnyBitPattern>(&mut self) -> Result<T> {
        let mut t = MaybeUninit::<T>::zeroed();
        // SAFETY: t owns size_of::<T>() bytes. zeroed() initialized all of
        // them, which makes them valid u8 values.
        let s = unsafe { from_raw_parts_mut(t.as_mut_ptr() as *mut u8, size_of::<T>()) };
        self.read_exact(s)?;
        // SAFETY: read_exact filled every byte, and T accepts any bit pattern.
        Ok(unsafe { t.assume_init() })
    }
}

pub trait TypeSave: Write {
    fn save<T: Sized + Copy>(&mut self, value: &T) -> Result<()> {
        let p = value as *const T as *const u8;
        let s = unsafe { from_raw_parts(p, size_of::<T>()) };
        self.write_all(s)
    }
}

impl<T: Read> TypeLoad for T {}
impl<T: Write> TypeSave for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_reads_value() {
        let mut reader: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
        let value: [u32; 2] = reader.load().unwrap();
        assert_eq!(
            value,
            [
                u32::from_ne_bytes([1, 2, 3, 4]),
                u32::from_ne_bytes([5, 6, 7, 8])
            ]
        );
    }

    #[test]
    fn test_load_short_input() {
        let mut reader: &[u8] = &[1, 2, 3];
        let err = reader.load::<u32>().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
