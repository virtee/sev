// SPDX-License-Identifier: Apache-2.0

//! Internal utilities shared across the crate.
//!
//! - [`parser_helper`] — [`Read`](std::io::Read) / [`Write`](std::io::Write)
//!   extensions for [`crate::parser`] decode/encode impls (`snp` or `sev` +
//!   `reference` for offline measurement wire types)
//! - [`hexline`](self::hexline) — hex formatting for debug display
//! - [`cached_chain`](self::cached_chain) — test helper for fetching AMD cert chains
//! - [`openssl_helpers`](self::openssl_helpers) — OpenSSL little-endian conversions
//!   (`crypto-openssl` with SNP verification or legacy SEV endorsement)

// pub mod array;
pub mod cached_chain;
pub(crate) mod hexline;
mod impl_const_id;
#[cfg(all(
    feature = "crypto-openssl",
    any(
        all(feature = "verifier", feature = "snp"),
        all(feature = "endorser", feature = "sev")
    )
))]
pub(crate) mod openssl_helpers;
#[cfg(any(feature = "snp", all(feature = "sev", feature = "reference")))]
pub mod parser_helper;

#[cfg(feature = "sev")]
use std::{
    io::{Read, Result, Write},
    mem::{size_of, MaybeUninit},
    slice::{from_raw_parts, from_raw_parts_mut},
};

#[cfg(feature = "sev")]
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

#[cfg(feature = "sev")]
pub trait TypeSave: Write {
    fn save<T: Sized + Copy>(&mut self, value: &T) -> Result<()> {
        let p = value as *const T as *const u8;
        let s = unsafe { from_raw_parts(p, size_of::<T>()) };
        self.write_all(s)
    }
}

#[cfg(feature = "sev")]
impl<T: Read> TypeLoad for T {}
#[cfg(feature = "sev")]
impl<T: Write> TypeSave for T {}
