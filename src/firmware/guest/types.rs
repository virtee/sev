// SPDX-License-Identifier: Apache-2.0

//! Guest `/dev/sev-guest` ioctl request and response layouts.
//!
//! C-compatible structs passed to the Linux kernel for SNP guest operations.
//! Higher-level Rust types in [`crate::types::snp`] convert into these layouts
//! before ioctl submission.
//!
//! # Response sizing
//!
//! [`ReportRsp`] is padded to exactly 4000 bytes so the guest response buffer
//! fits within a single 4 KiB page (96-byte message header + encrypted payload).
//! The attestation report itself is 1184 bytes ([`ReportRsp::report`]).

use crate::{error::*, types::snp::DerivedKey};

use static_assertions::const_assert;

/// Maximum valid VMPL value for report and derived-key requests.
///
/// May become `4` when the Shadow Stack feature is enabled.
/// [APMv2 - Table 15-38 - VMPL Permission Mask Definition](https://www.amd.com/system/files/TechDocs/24593.pdf#page=670&zoom=100,0,400)
const MAX_VMPL: u32 = 3;

/// Request payload for `SNP_GET_DERIVED_KEY`.
#[repr(C)]
#[derive(Debug, Default)]
pub struct DerivedKeyReq {
    /// Root key selector: `0` = VCEK, `1` = VMRK.
    root_key_select: u32,

    /// Reserved, must be zero.
    reserved_0: u32,

    /// Guest field selector bitmask mixed into the derived key.
    pub guest_field_select: u64,

    /// VMPL to mix into the key. Must be >= current VMPL and <= [`MAX_VMPL`].
    pub vmpl: u32,

    /// Guest SVN to mix into the key. Must not exceed the launch ID block SVN.
    pub guest_svn: u32,

    /// TCB version to mix into the key. Must not exceed committed TCB.
    pub tcb_version: u64,

    /// Mitigation vector mixed into the key (FW 1.58+; defaults to 0).
    pub launch_mit_vector: u64,
}

impl From<DerivedKey> for DerivedKeyReq {
    fn from(value: DerivedKey) -> Self {
        Self {
            root_key_select: value.get_root_key_select(),
            reserved_0: Default::default(),
            guest_field_select: value.guest_field_select.0,
            vmpl: value.vmpl,
            guest_svn: value.guest_svn,
            tcb_version: value.tcb_version,
            launch_mit_vector: value.launch_mit_vector.unwrap_or(0),
        }
    }
}

impl From<&mut DerivedKey> for DerivedKeyReq {
    fn from(value: &mut DerivedKey) -> Self {
        Self {
            root_key_select: value.get_root_key_select(),
            reserved_0: Default::default(),
            guest_field_select: value.guest_field_select.0,
            vmpl: value.vmpl,
            guest_svn: value.guest_svn,
            tcb_version: value.tcb_version,
            launch_mit_vector: value.launch_mit_vector.unwrap_or(0),
        }
    }
}

/// Response from `SNP_GET_DERIVED_KEY`.
#[derive(Default, Debug)]
#[repr(C)]
pub struct DerivedKeyRsp {
    /// Operation status: `0` = success, `0x16` = invalid parameters.
    pub status: u32,

    reserved_0: [u8; 28],

    /// 32-byte derived key when [`status`](Self::status) is `0`.
    pub key: [u8; 32],
}

/// Request payload for `SNP_GET_EXT_REPORT`.
///
/// Extends [`ReportReq`] with a guest-virtual address and length for the
/// firmware certificate table. The certificate buffer should be page-aligned
/// for the kernel driver.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExtReportReq {
    /// Base report request parameters.
    pub data: ReportReq,

    /// Guest-virtual address of the certificate data buffer.
    pub certs_address: u64,

    /// Page-aligned length of the certificate buffer.
    pub certs_len: u32,
}

impl ExtReportReq {
    /// Create an extended report request without a certificate buffer.
    ///
    /// Sets `certs_address` to `u64::MAX` and `certs_len` to `0`, indicating
    /// no certificate table is requested.
    pub fn new(data: &ReportReq) -> Self {
        Self {
            data: *data,
            certs_address: u64::MAX,
            certs_len: 0u32,
        }
    }
}

/// Request payload for `SNP_GET_REPORT`.
///
/// Carries guest-provided report data (64 bytes) and the VMPL level to embed
/// in the generated attestation report.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct ReportReq {
    /// Guest-provided data included in the attestation report.
    report_data: [u8; 64],

    /// VMPL for the report. Must be >= current VMPL and at most [`MAX_VMPL`].
    vmpl: u32,

    /// Reserved, must be zero.
    _reserved: [u8; 28],
}

impl Default for ReportReq {
    fn default() -> Self {
        Self {
            report_data: [0; 64],
            vmpl: 1,
            _reserved: Default::default(),
        }
    }
}

impl ReportReq {
    /// Build a report request for the ASP.
    ///
    /// # Arguments
    ///
    /// * `report_data` — optional 64 bytes of guest nonce/data for the report
    /// * `vmpl` — optional VMPL override (defaults to `1`)
    ///
    /// # Errors
    ///
    /// Returns [`UserApiError::VmplError`] when `vmpl` exceeds [`MAX_VMPL`].
    pub fn new(report_data: Option<[u8; 64]>, vmpl: Option<u32>) -> Result<Self, UserApiError> {
        let mut request = Self::default();

        if let Some(report_data) = report_data {
            request.report_data = report_data;
        }

        if let Some(vmpl) = vmpl {
            if vmpl > MAX_VMPL {
                return Err(UserApiError::VmplError);
            } else {
                request.vmpl = vmpl;
            }
        }

        Ok(request)
    }
}

const REPORT_SIZE: usize = 1184usize;

/// Response from `SNP_GET_REPORT` / `SNP_GET_EXT_REPORT`.
///
/// Padded to exactly 4000 bytes for 4 KiB page alignment:
///
/// ```text
///     96 Bytes (*Message Header)
/// + 4000 Bytes (*Encrypted Message)
/// ------------
///   4096 Bytes (4K Memory Page Alignment)
/// ```
/// <sup>*[Message Header - 8.26 SNP_GUEST_REQUEST - Table 97](<https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf#page=113>)</sup>
///
/// <sup>*[Encrypted Message - sev-guest.h](<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/sev-guest.h>)</sup>
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ReportRsp {
    /// Operation status: `0` = success, `0x16` = invalid parameters.
    pub status: u32,
    /// Size in bytes of the valid portion of [`report`](Self::report).
    pub report_size: u32,
    reserved_0: [u8; 24],
    /// Raw 1184-byte attestation report from the firmware.
    pub report: [u8; REPORT_SIZE],
    /// Padding to reach the 4000-byte encrypted-message size.
    reserved_1: [u8; 4000
        - (REPORT_SIZE + (std::mem::size_of::<u32>() * 2) + std::mem::size_of::<[u8; 24]>())],
}

// Compile-time check that the size is what is expected.
// Will error out with:
//
//      evaluation of constant value failed attempt to compute
//      `0_usize - 1_usize`, which would overflow
//
const_assert!(std::mem::size_of::<ReportRsp>() == 4000);

impl Default for ReportRsp {
    fn default() -> Self {
        Self {
            status: Default::default(),
            report_size: Default::default(),
            reserved_0: Default::default(),
            report: [0u8; REPORT_SIZE],
            reserved_1: [0u8; 4000
                - (REPORT_SIZE
                    + (std::mem::size_of::<u32>() * 2)
                    + std::mem::size_of::<[u8; 24]>())],
        }
    }
}

#[cfg(test)]
mod test {
    mod snp_report_req {
        use super::super::ReportReq;

        #[test]
        pub fn test_new() {
            let report_data: [u8; 64] = [
                65, 77, 68, 32, 105, 115, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 97,
                119, 101, 115, 111, 109, 101, 33, 32, 87, 101, 32, 109, 97, 107, 101, 32, 116, 104,
                101, 32, 98, 101, 115, 116, 32, 67, 80, 85, 115, 33, 32, 65, 77, 68, 32, 82, 111,
                99, 107, 115, 33, 33, 33, 33, 33, 33,
            ];
            let expected: ReportReq = ReportReq {
                report_data,
                vmpl: 0,
                _reserved: [0; 28],
            };

            let actual: ReportReq = ReportReq::new(Some(report_data), Some(0)).unwrap();

            assert_eq!(expected, actual);
        }

        #[test]
        #[should_panic]
        pub fn test_new_error() {
            let report_data: [u8; 64] = [
                65, 77, 68, 32, 105, 115, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 97,
                119, 101, 115, 111, 109, 101, 33, 32, 87, 101, 32, 109, 97, 107, 101, 32, 116, 104,
                101, 32, 98, 101, 115, 116, 32, 67, 80, 85, 115, 33, 32, 65, 77, 68, 32, 82, 111,
                99, 107, 115, 33, 33, 33, 33, 33, 33,
            ];
            let expected: ReportReq = ReportReq {
                report_data,
                vmpl: 7,
                _reserved: [0; 28],
            };

            let actual: ReportReq = ReportReq::new(Some(report_data), Some(0)).unwrap();

            assert_eq!(expected, actual);
        }
    }

    use crate::types::snp::GuestFieldSelect;

    use super::*;

    #[test]
    fn test_derived_key_req_conversion() {
        // Create a mock DerivedKey
        let derived_key = DerivedKey::new(false, GuestFieldSelect(0x1234), 2, 1, 100, Some(123));

        // Test From<DerivedKey>
        let req: DerivedKeyReq = derived_key.into();
        assert_eq!(req.root_key_select, 0);
        assert_eq!(req.reserved_0, 0);
        assert_eq!(req.guest_field_select, 0x1234);
        assert_eq!(req.vmpl, 2);
        assert_eq!(req.guest_svn, 1);
        assert_eq!(req.tcb_version, 100);
        assert_eq!(req.launch_mit_vector, 123);

        // Test From<&mut DerivedKey>
        let mut derived_key = derived_key;
        let req: DerivedKeyReq = (&mut derived_key).into();
        assert_eq!(req.root_key_select, 0);
        assert_eq!(req.reserved_0, 0);
        assert_eq!(req.guest_field_select, 0x1234);
        assert_eq!(req.vmpl, 2);
        assert_eq!(req.guest_svn, 1);
        assert_eq!(req.tcb_version, 100);
        assert_eq!(req.launch_mit_vector, 123);
    }

    #[test]
    fn test_ext_report_req() {
        let report_req = ReportReq::default();
        let ext_report = ExtReportReq::new(&report_req);

        assert_eq!(ext_report.data, report_req);
        assert_eq!(ext_report.certs_address, u64::MAX);
        assert_eq!(ext_report.certs_len, 0);

        // Test Default
        let default_ext = ExtReportReq::default();
        assert_eq!(default_ext.certs_address, 0);
        assert_eq!(default_ext.certs_len, 0);
    }

    #[test]
    fn test_report_req() {
        // Test default values
        let default_req = ReportReq::default();
        assert_eq!(default_req.report_data, [0; 64]);
        assert_eq!(default_req.vmpl, 1);
        assert_eq!(default_req._reserved, [0; 28]);

        // Test successful creation with Some values
        let report_data = [42u8; 64];
        let req = ReportReq::new(Some(report_data), Some(2)).unwrap();
        assert_eq!(req.report_data, report_data);
        assert_eq!(req.vmpl, 2);

        // Test successful creation with None values
        let req = ReportReq::new(None, None).unwrap();
        assert_eq!(req.report_data, [0; 64]);
        assert_eq!(req.vmpl, 1);

        // Test VMPL validation
        assert!(ReportReq::new(None, Some(4)).is_err());
        assert!(ReportReq::new(None, Some(MAX_VMPL)).is_ok());
    }

    #[test]
    fn test_report_rsp() {
        let rsp = ReportRsp::default();

        assert_eq!(rsp.status, 0);
        assert_eq!(rsp.report_size, 0);
        assert_eq!(rsp.reserved_0, [0; 24]);

        // Verify size is exactly 4000 bytes
        assert_eq!(std::mem::size_of::<ReportRsp>(), 4000);
    }

    #[test]
    fn test_derived_key_rsp() {
        let rsp = DerivedKeyRsp::default();

        assert_eq!(rsp.status, 0);
        assert_eq!(rsp.reserved_0, [0; 28]);
        assert_eq!(rsp.key, [0; 32]);
    }
}
