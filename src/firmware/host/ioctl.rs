// SPDX-License-Identifier: Apache-2.0

//! Type-safe ioctl bindings for the Linux `/dev/sev` device.
//!
//! Defines the ioctl group (`'S'`), command identifiers, and the [`Command`]
//! envelope used to pass sub-command pointers to the kernel. Payload layouts
//! are in [`super::types`].
//!
//! Kernel UAPI reference: `include/uapi/linux/psp-sev.h`.
//!
//! # Ioctl summary
//!
//! ## Shared (legacy SEV and SEV-SNP)
//!
//! These ioctls and payloads are available whenever `platform` is enabled and
//! either `sev` or `snp` is active. SNP-only builds still use them for CPU ID
//! lookup and legacy platform status:
//!
//! | Constant | Payload | Purpose |
//! |----------|---------|---------|
//! | `PLATFORM_STATUS` | [`PlatformStatus`](super::types::PlatformStatus) | Legacy SEV platform status |
//! | `GET_ID` | [`GetId`](super::types::GetId) | CPU unique identifier |
//!
//! ## Legacy SEV only (`sev` feature)
//!
//! | Constant | Purpose |
//! |----------|---------|
//! | `PLATFORM_RESET` | Reset platform persistent state |
//! | `PEK_GEN` / `PEK_CSR` / `PEK_CERT_IMPORT` | Platform endorsement key provisioning |
//! | `PDH_GEN` / `PDH_CERT_EXPORT` | Platform Diffie-Hellman key export |
//!
//! ## SEV-SNP only (`snp` feature)
//!
//! | Constant | Purpose |
//! |----------|---------|
//! | `SNP_PLATFORM_STATUS` | SNP platform status |
//! | `SNP_COMMIT` | Commit firmware TCB/version |
//! | `SNP_SET_CONFIG` | Set reported TCB and mask ID |
//! | `SNP_VLEK_LOAD` | Load VLEK hashstick |

use super::types::*;

use crate::impl_const_id;

use crate::error::FirmwareError;

use std::marker::PhantomData;

use iocuddle::*;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/psp-sev.h
#[cfg(all(feature = "sev", feature = "snp"))]
impl_const_id! {
    pub Id => u32;

    PlatformReset = 0x0,
    PlatformStatus = 0x1,
    PekGen = 0x2,
    PekCsr<'_> = 0x3,
    PdhGen = 0x4,
    PdhCertExport<'_> = 0x5,
    PekCertImport<'_> = 0x6,
    GetId<'_> = 0x8, /* GET_ID2 is 0x8, the deprecated GET_ID ioctl is 0x7 */

    SnpPlatformStatus = 0x9,
    SnpCommit = 0xA,
    SnpSetConfig = 0xB,
    SnpVlekLoad = 0xC,
}

#[cfg(all(feature = "sev", not(feature = "snp")))]
impl_const_id! {
    pub Id => u32;

    PlatformReset = 0x0,
    PlatformStatus = 0x1,
    PekGen = 0x2,
    PekCsr<'_> = 0x3,
    PdhGen = 0x4,
    PdhCertExport<'_> = 0x5,
    PekCertImport<'_> = 0x6,
    GetId<'_> = 0x8, /* GET_ID2 is 0x8, the deprecated GET_ID ioctl is 0x7 */
}

#[cfg(all(not(feature = "sev"), feature = "snp"))]
impl_const_id! {
    pub Id => u32;

    GetId<'_> = 0x8, /* GET_ID2 is 0x8, the deprecated GET_ID ioctl is 0x7 */
    PlatformStatus = 0x1,
    SnpPlatformStatus = 0x9,
    SnpCommit = 0xA,
    SnpSetConfig = 0xB,
    SnpVlekLoad = 0xC,
}

const SEV: Group = Group::new(b'S');

/// Reset the SEV platform's persistent state.
#[cfg(feature = "sev")]
pub const PLATFORM_RESET: Ioctl<WriteRead, &Command<PlatformReset>> = unsafe { SEV.write_read(0) };

/// Query legacy SEV platform status.
///
/// Shared ioctl: available on both legacy SEV and SEV-SNP hosts.
#[cfg(any(feature = "sev", feature = "snp"))]
pub const PLATFORM_STATUS: Ioctl<WriteRead, &Command<PlatformStatus>> =
    unsafe { SEV.write_read(0) };

/// Generate a new Platform Endorsement Key (PEK).
#[cfg(feature = "sev")]
pub const PEK_GEN: Ioctl<WriteRead, &Command<PekGen>> = unsafe { SEV.write_read(0) };

/// Request PEK certificate signing (CSR).
#[cfg(feature = "sev")]
pub const PEK_CSR: Ioctl<WriteRead, &Command<PekCsr<'_>>> = unsafe { SEV.write_read(0) };

/// (Re)generate the Platform Diffie-Hellman (PDH) key.
#[cfg(feature = "sev")]
pub const PDH_GEN: Ioctl<WriteRead, &Command<PdhGen>> = unsafe { SEV.write_read(0) };

/// Export the PDH and platform certificate chain.
#[cfg(feature = "sev")]
pub const PDH_CERT_EXPORT: Ioctl<WriteRead, &Command<PdhCertExport<'_>>> =
    unsafe { SEV.write_read(0) };

/// Import PEK and OCA certificates to join the platform to a domain.
#[cfg(feature = "sev")]
pub const PEK_CERT_IMPORT: Ioctl<WriteRead, &Command<PekCertImport<'_>>> =
    unsafe { SEV.write_read(0) };

/// Read the CPU unique identifier (for CEK certificate lookup).
///
/// Shared ioctl: available on both legacy SEV and SEV-SNP hosts.
#[cfg(any(feature = "sev", feature = "snp"))]
pub const GET_ID: Ioctl<WriteRead, &Command<GetId<'_>>> = unsafe { SEV.write_read(0) };

/// Query SNP platform status and capabilities.
#[cfg(feature = "snp")]
pub const SNP_PLATFORM_STATUS: Ioctl<WriteRead, &Command<SnpPlatformStatus>> =
    unsafe { SEV.write_read(0) };

/// Commit the current firmware TCB and version.
///
/// The firmware will:
/// - Set `CommittedTCB` to the current firmware TCB.
/// - Set `CommittedVersion` to the current firmware version.
/// - Set `ReportedTCB` to the current TCB.
/// - Delete the VLEK hashstick if `ReportedTCB` changed.
#[cfg(feature = "snp")]
pub const SNP_COMMIT: Ioctl<WriteRead, &Command<SnpCommit>> = unsafe { SEV.write_read(0) };

/// Set system-wide SNP configuration (reported TCB, mask ID).
#[cfg(feature = "snp")]
pub const SNP_SET_CONFIG: Ioctl<WriteRead, &Command<SnpSetConfig>> = unsafe { SEV.write_read(0) };

/// Load a VLEK hashstick for VLEK-based attestation.
#[cfg(feature = "snp")]
pub const SNP_VLEK_LOAD: Ioctl<WriteRead, &Command<SnpVlekLoad>> = unsafe { SEV.write_read(0) };

/// Envelope passed to every `/dev/sev` ioctl.
///
/// Rust/FFI-friendly mirror of the kernel's `struct sev_issue_cmd` from
/// `include/uapi/linux/psp-sev.h`. Carries the sub-command ID, a pointer to
/// the payload, and a firmware error code populated on failure.
#[repr(C, packed)]
pub struct Command<'a, T: Id> {
    /// Sub-command identifier (see [`Id`]).
    pub code: u32,
    /// Host-virtual address of the sub-command payload.
    pub data: u64,
    /// Firmware error code written by the kernel on failure.
    pub error: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// Build a command whose payload may be mutated by the kernel.
    ///
    /// Use when the ioctl writes results back into `subcmd` or a buffer
    /// referenced by `subcmd`.
    pub fn from_mut(subcmd: &'a mut T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }

    /// Build a command with a read-only payload reference.
    ///
    /// Semantic hint that the kernel should not mutate caller memory. Note that
    /// this does not prevent the kernel from writing if the UAPI allows it.
    #[cfg(feature = "sev")]
    pub fn from(subcmd: &'a T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *const T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }

    /// Convert the firmware error word into a [`FirmwareError`].
    pub fn encapsulate(&self) -> FirmwareError {
        FirmwareError::from(self.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_get_id() {
        let mut id = [0u8; 64];
        let mut data = GetId::new(&mut id);
        let cmd = Command::<GetId>::from_mut(&mut data);
        let code = cmd.code;
        let error = cmd.error;
        assert_eq!(code, GetId::ID);
        assert_eq!(error, 0);
    }

    #[cfg(any(feature = "sev", feature = "snp"))]
    mod platform_status_tests {
        use super::super::*;

        #[test]
        fn test_command_platform_status() {
            let mut data = PlatformStatus::default();
            let cmd = Command::<PlatformStatus>::from_mut(&mut data);
            let code = cmd.code;
            let error = cmd.error;
            assert_eq!(code, PlatformStatus::ID);
            assert_eq!(error, 0);
        }

        #[cfg(feature = "sev")]
        #[test]
        fn test_command_platform_status_non_mut() {
            let data = PlatformStatus::default();
            let cmd = Command::<PlatformStatus>::from(&data);
            let code = cmd.code;
            let error = cmd.error;
            assert_eq!(code, PlatformStatus::ID);
            assert_eq!(error, 0);
        }
        #[test]
        fn test_command_error_encapsulation() {
            // Test with success (0)
            let cmd = Command::<PlatformStatus> {
                code: PlatformStatus::ID,
                error: 0,
                data: 0,
                _phantom: PhantomData,
            };

            let error = cmd.encapsulate();
            assert!(matches!(error, FirmwareError::IoError(_)));
        }
    }
}
