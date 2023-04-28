// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "sev")]
mod sev;

#[cfg(feature = "snp")]
mod snp;

#[cfg(feature = "sev")]
pub use self::sev::*;

#[cfg(feature = "snp")]
pub use self::snp::*;

#[cfg(any(feature = "sev", feature = "snp"))]
use std::marker::PhantomData;

/// Get the CPU's unique ID that can be used for getting
/// a certificate for the CEK public key.
#[cfg(any(feature = "sev", feature = "snp"))]
#[repr(C, packed)]
pub struct GetId<'a> {
    id_addr: u64,
    id_len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(any(feature = "sev", feature = "snp"))]
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
