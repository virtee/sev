// SPDX-License-Identifier: Apache-2.0

//! A collection of type-safe ioctl implementations for the AMD Secure Encrypted Virtualization
//! (SEV) platform. These ioctls are exported by the Linux kernel.

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
    SnpPlatformStatus = 0x9,
    SnpCommit = 0xA,
    SnpSetConfig = 0xB,
    SnpVlekLoad = 0xC,
}

const SEV: Group = Group::new(b'S');

/// Resets the SEV platform's persistent state.
#[cfg(feature = "sev")]
pub const PLATFORM_RESET: Ioctl<WriteRead, &Command<PlatformReset>> = unsafe { SEV.write_read(0) };

/// Gathers a status report from the SEV firmware.
#[cfg(feature = "sev")]
pub const PLATFORM_STATUS: Ioctl<WriteRead, &Command<PlatformStatus>> =
    unsafe { SEV.write_read(0) };

/// Generate a new Platform Endorsement Key (PEK).
#[cfg(feature = "sev")]
pub const PEK_GEN: Ioctl<WriteRead, &Command<PekGen>> = unsafe { SEV.write_read(0) };

/// Take ownership of the platform.
#[cfg(feature = "sev")]
pub const PEK_CSR: Ioctl<WriteRead, &Command<PekCsr<'_>>> = unsafe { SEV.write_read(0) };

/// (Re)generate the Platform Diffie-Hellman (PDH).
#[cfg(feature = "sev")]
pub const PDH_GEN: Ioctl<WriteRead, &Command<PdhGen>> = unsafe { SEV.write_read(0) };

/// Retrieve the PDH and the platform certificate chain.
#[cfg(feature = "sev")]
pub const PDH_CERT_EXPORT: Ioctl<WriteRead, &Command<PdhCertExport<'_>>> =
    unsafe { SEV.write_read(0) };

/// Join the platform to the domain.
#[cfg(feature = "sev")]
pub const PEK_CERT_IMPORT: Ioctl<WriteRead, &Command<PekCertImport<'_>>> =
    unsafe { SEV.write_read(0) };

/// Get the CPU's unique ID that can be used for getting a certificate for the CEK public key.
#[cfg(any(feature = "sev", feature = "snp"))]
pub const GET_ID: Ioctl<WriteRead, &Command<GetId<'_>>> = unsafe { SEV.write_read(0) };

/// Return information about the current status and capabilities of the SEV-SNP platform.
#[cfg(feature = "snp")]
pub const SNP_PLATFORM_STATUS: Ioctl<WriteRead, &Command<SnpPlatformStatus>> =
    unsafe { SEV.write_read(0) };

/// The firmware will perform the following actions:
/// - Set the CommittedTCB to the CurrentTCB of the current firmware.
/// - Set the CommittedVersion to the FirmwareVersion of the current firmware.
/// - Sets the ReportedTCB to the CurrentTCB.
/// - Deletes the VLEK hashstick if the ReportedTCB changed.
///
/// C IOCTL calls -> sev_ioctl_do_snp_commit
#[cfg(feature = "snp")]
pub const SNP_COMMIT: Ioctl<WriteRead, &Command<SnpCommit>> = unsafe { SEV.write_read(0) };

/// Set the system-wide configuration such as reported TCB version in the attestation report
/// C IOCTL calls -> sev_ioctl_do_snp_set_config
#[cfg(feature = "snp")]
pub const SNP_SET_CONFIG: Ioctl<WriteRead, &Command<SnpSetConfig>> = unsafe { SEV.write_read(0) };

#[cfg(feature = "snp")]
/// Load a specified VLEK hashstick into the AMD Secure Processor to be used in place of VCEK.
pub const SNP_VLEK_LOAD: Ioctl<WriteRead, &Command<SnpVlekLoad>> = unsafe { SEV.write_read(0) };

/// The Rust-flavored, FFI-friendly version of `struct sev_issue_cmd` which is
/// used to pass arguments to the SEV ioctl implementation.
///
/// This struct is defined in the Linux kernel: include/uapi/linux/psp-sev.h
#[repr(C, packed)]
pub struct Command<'a, T: Id> {
    pub code: u32,
    pub data: u64,
    pub error: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// Create an SEV command with the expectation that the host platform/kernel will write to
    /// the caller's address space either to the data held in the `Command.subcmd` field or some
    /// other region specified by the `Command.subcmd` field.
    pub fn from_mut(subcmd: &'a mut T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }

    /// Create an SEV command with the expectation that the host platform/kernel *WILL NOT* mutate
    /// the caller's address space in its response. Note: this does not actually prevent the host
    /// platform/kernel from writing to the caller's address space if it wants to. This is primarily
    /// a semantic tool for programming against the SEV ioctl API.
    #[cfg(feature = "sev")]
    pub fn from(subcmd: &'a T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *const T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }

    /// encapsulate a SEV errors in command as a Firmware error.
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

    #[cfg(feature = "sev")]
    mod sev_specific_tests {
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
