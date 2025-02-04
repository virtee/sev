// SPDX-License-Identifier: Apache-2.0

//! Helpful primitives for developing the crate.

pub mod cached_chain;
mod impl_const_id;
pub mod large_array;
pub(crate) mod sealed;

use std::{
    io::{Read, Result, Write},
    mem::{size_of, MaybeUninit},
    slice::{from_raw_parts, from_raw_parts_mut},
};

#[cfg(any(feature = "sev", feature = "snp"))]
pub fn hexdump(bytes: &[u8]) -> String {
    let mut retval: String = String::new();
    for (i, byte) in bytes.iter().enumerate() {
        if (i % 16) == 0 {
            retval.push('\n');
        }
        retval.push_str(&format!("{byte:02x} "));
    }
    retval.push('\n');
    retval
}

pub trait TypeLoad: Read {
    fn load<T: Sized + Copy>(&mut self) -> Result<T> {
        #[allow(clippy::uninit_assumed_init)]
        let mut t = unsafe { MaybeUninit::uninit().assume_init() };
        let p = &mut t as *mut T as *mut u8;
        let s = unsafe { from_raw_parts_mut(p, size_of::<T>()) };
        self.read_exact(s)?;
        Ok(t)
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
