// SPDX-License-Identifier: Apache-2.0

//! SNP host ioctl payload layouts.
//!
//! Structures for SEV-SNP platform management ioctls: status query, TCB commit,
//! system configuration, and VLEK hashstick loading.
//!
//! Public wrappers are in [`crate::platform::snp`]. Decoded wire types live in
//! [`crate::types::snp`].

use std::{
    convert::TryFrom,
    ops::{Deref, DerefMut},
};

use crate::{error::HashstickError, types::snp::MaskId};

/// Expected byte length of a VLEK hashstick ioctl buffer.
pub const HASHSTICK_BUFFER_LEN: usize = 432;

/// Payload for the `SNP_COMMIT` ioctl.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct SnpCommit {
    /// Reserved buffer field (must be zero).
    pub buffer: u32,
}

/// Payload for the `SNP_SET_CONFIG` ioctl.
///
/// Sets the reported TCB version and mask ID used in attestation reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SnpSetConfig {
    /// Reported TCB version bytes written to attestation reports.
    pub reported_tcb: [u8; 8],
    /// Platform mask identifier.
    pub mask_id: MaskId,
    reserved: [u8; 52],
}

impl Default for SnpSetConfig {
    fn default() -> Self {
        Self {
            reported_tcb: Default::default(),
            mask_id: Default::default(),
            reserved: [0; 52],
        }
    }
}

impl SnpSetConfig {
    /// Build a set-config payload from reported TCB bytes and a mask ID.
    pub fn new(reported_tcb: [u8; 8], mask_id: MaskId) -> Self {
        Self {
            reported_tcb,
            mask_id,
            reserved: [0; 52],
        }
    }
}

/// Validated VLEK hashstick bytes for `SNP_VLEK_LOAD`.
///
/// Enforces buffer length and reserved-field constraints before the ioctl
/// payload is constructed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
pub struct WrappedVlekHashstick {
    /// 432-byte wrapped hashstick from AMD.
    pub data: [u8; HASHSTICK_BUFFER_LEN],
}

impl TryFrom<&[u8]> for WrappedVlekHashstick {
    type Error = HashstickError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != HASHSTICK_BUFFER_LEN {
            return Err(HashstickError::InvalidLength);
        }

        if value == [0u8; HASHSTICK_BUFFER_LEN] {
            return Err(HashstickError::EmptyHashstickBuffer);
        }

        if value[0x0C..0x10] != [0u8; 4] {
            return Err(HashstickError::InvalidReservedField);
        }

        if value[0x198..0x1A0] != [0u8; 8] {
            return Err(HashstickError::InvalidReservedField);
        }

        let mut data = [0u8; HASHSTICK_BUFFER_LEN];
        data.copy_from_slice(value);

        Ok(Self { data })
    }
}

/// Payload for the `SNP_VLEK_LOAD` ioctl.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SnpVlekLoad {
    /// Size of this structure.
    pub len: u32,
    /// Wrapped hashstick format version.
    pub vlek_wrapped_version: u8,
    _reserved: [u8; 3],
    /// Host-virtual address of a [`WrappedVlekHashstick`].
    pub vlek_wrapped_address: u64,
}

impl SnpVlekLoad {
    /// Build a VLEK load payload from a validated hashstick.
    pub fn new(hashstick: &WrappedVlekHashstick) -> Self {
        hashstick.into()
    }
}

impl From<&WrappedVlekHashstick> for SnpVlekLoad {
    fn from(value: &WrappedVlekHashstick) -> Self {
        Self {
            len: std::mem::size_of::<SnpVlekLoad>() as u32,
            vlek_wrapped_version: 0u8,
            _reserved: Default::default(),
            vlek_wrapped_address: value as *const WrappedVlekHashstick as u64,
        }
    }
}

/// Raw 32-byte buffer returned by the `SNP_PLATFORM_STATUS` ioctl.
///
/// Decode with [`crate::platform::Firmware::snp_platform_status`] using an
/// explicit [`Generation`](crate::types::shared::Generation).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SnpPlatformStatus {
    pub buffer: [u8; 32],
}

impl Deref for SnpPlatformStatus {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for SnpPlatformStatus {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl AsRef<[u8]> for SnpPlatformStatus {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

impl AsMut<[u8]> for SnpPlatformStatus {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snp_set_config_default() {
        let expected = SnpSetConfig {
            reported_tcb: Default::default(),
            mask_id: Default::default(),
            reserved: [0; 52],
        };
        assert_eq!(expected, SnpSetConfig::default());
    }

    #[cfg(target_os = "linux")]
    mod hashstick {
        use super::*;

        fn valid_hashstick_bytes() -> [u8; HASHSTICK_BUFFER_LEN] {
            let mut bytes = [1u8; HASHSTICK_BUFFER_LEN];
            bytes[0x0C..0x10].copy_from_slice(&[0u8; 4]);
            bytes[0x198..0x1A0].copy_from_slice(&[0u8; 8]);
            bytes
        }

        #[test]
        fn bytes_to_wrapped_hashstick() {
            let bytes = valid_hashstick_bytes();
            let expected = WrappedVlekHashstick { data: bytes };
            let actual = WrappedVlekHashstick::try_from(bytes.as_slice()).unwrap();
            assert_eq!(actual, expected);
        }

        #[test]
        fn wrapped_hashstick_into_snp_vlek_load() {
            let test_hashstick =
                WrappedVlekHashstick::try_from(valid_hashstick_bytes().as_slice()).unwrap();
            let actual: SnpVlekLoad = (&test_hashstick).into();
            assert_eq!(actual.vlek_wrapped_version, 0);
        }
    }
}
