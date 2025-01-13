// SPDX-License-Identifier: Apache-2.0

#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
#[cfg(feature = "sev")]
mod sev;

#[cfg(feature = "snp")]
mod snp;

#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
#[cfg(feature = "sev")]
pub use self::sev::*;

#[cfg(feature = "snp")]
pub use self::snp::*;

#[cfg(any(feature = "sev", feature = "snp"))]
#[cfg(target_os = "linux")]
use std::marker::PhantomData;

/// Get the CPU's unique ID that can be used for getting
/// a certificate for the CEK public key.
#[cfg(target_os = "linux")]
#[cfg(any(feature = "sev", feature = "snp"))]
#[repr(C, packed)]
pub struct GetId<'a> {
    id_addr: u64,
    id_len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(any(feature = "sev", feature = "snp"))]
#[cfg(target_os = "linux")]
impl<'a> GetId<'a> {
    pub fn new(id: &'a mut [u8; 64]) -> Self {
        Self {
            id_addr: id.as_mut_ptr() as _,
            id_len: id.len() as _,
            _phantom: PhantomData,
        }
    }

    /// This method is only meaningful if called *after* the GET_ID2 ioctl is called because the
    /// kernel will write the length of the unique CPU ID to `GetId.id_len`.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.id_addr as *const u8, self.id_len as _) }
    }
}

/// Reset the platform's persistent state.
///
/// (Chapter 5.5)
#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
#[cfg(feature = "sev")]
#[cfg(target_os = "linux")]
pub struct PlatformReset;
