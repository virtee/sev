// SPDX-License-Identifier: Apache-2.0

//! Host ioctl payloads shared by legacy SEV and SEV-SNP.
//!
//! These layouts back ioctls available on `/dev/sev` regardless of whether the
//! `sev` or `snp` feature is enabled:
//!
//! | Payload | Ioctl constant | Used by |
//! |---------|----------------|---------|
//! | [`PlatformStatus`] | [`PLATFORM_STATUS`](super::super::ioctl::PLATFORM_STATUS) | Both legacy SEV and SNP platform code |
//! | [`GetId`] | [`GET_ID`](super::super::ioctl::GET_ID) | Both (CPU identifier for CEK/VCEK lookup) |
//!
//! Legacy-only and SNP-only payloads live in [`super::sev`] and [`super::snp`].

#[cfg(target_os = "linux")]
use std::marker::PhantomData;

use crate::types::sev::{PlatformStatusFlags, Version};

/// Legacy SEV platform status query payload.
///
/// Populated by the shared `PLATFORM_STATUS` ioctl on `/dev/sev`. Valid on both
/// legacy SEV and SEV-SNP hosts. See AMD SEV API specification chapter 5.6,
/// table 17.
#[derive(Default)]
#[repr(C, packed)]
pub struct PlatformStatus {
    /// Firmware API version (major/minor).
    pub version: Version,

    /// Platform lifecycle state.
    pub state: u8,

    /// Self-owned and ES-enabled flags.
    pub flags: PlatformStatusFlags,

    /// Firmware build ID for this API version.
    pub build: u8,

    /// Number of active guests tracked by the firmware.
    pub guest_count: u32,
}

/// CPU unique identifier query payload for the shared `GET_ID` / `GET_ID2` ioctl.
///
/// Available on both legacy SEV and SEV-SNP hosts. The kernel writes the actual
/// ID length to [`Self::id_len`] on success.
#[cfg(target_os = "linux")]
#[repr(C, packed)]
pub struct GetId<'a> {
    id_addr: u64,
    id_len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(target_os = "linux")]
impl<'a> GetId<'a> {
    /// Build a GET_ID payload pointing at a 64-byte buffer.
    pub fn new(id: &'a mut [u8; 64]) -> Self {
        Self {
            id_addr: id.as_mut_ptr() as _,
            id_len: id.len() as _,
            _phantom: PhantomData,
        }
    }

    /// View the identifier bytes after a successful ioctl.
    ///
    /// Meaningful only after `GET_ID2`; the kernel updates `id_len` with the
    /// actual identifier length.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.id_addr as *const u8, self.id_len as _) }
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_id_new() {
        let mut id = [0u8; 64];
        let get_id = GetId::new(&mut id);

        assert_eq!(
            unsafe { std::ptr::addr_of!(get_id.id_len).read_unaligned() },
            64
        );
        assert_eq!(get_id.id_addr as *const u8, id.as_ptr());
    }

    #[test]
    fn test_get_id_slice() {
        let mut id = [42u8; 64];
        let get_id = GetId::new(&mut id);
        assert_eq!(get_id.as_slice(), &[42u8; 64]);
    }
}
