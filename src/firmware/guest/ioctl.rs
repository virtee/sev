// SPDX-License-Identifier: Apache-2.0

//! Ioctl bindings for the Linux `/dev/sev-guest` device.
//!
//! Defines the ioctl group (`'S'`), command numbers, and the
//! [`GuestRequest`] envelope used to pass request/response pointers to the
//! kernel. Request and response payload layouts are in [`super::types`].
//!
//! Kernel UAPI reference: `include/uapi/linux/sev-guest.h`.

use crate::firmware::guest::types::{
    DerivedKeyReq, DerivedKeyRsp, ExtReportReq, ReportReq, ReportRsp,
};

use std::marker::PhantomData;

use iocuddle::{Group, Ioctl, WriteRead};

/// Guest ioctl command numbers (Linux `sev-guest` UAPI).
pub enum GuestIoctl {
    /// Standard attestation report (`SNP_GET_REPORT`).
    GetReport = 0x0,
    /// Guest-derived key (`SNP_GET_DERIVED_KEY`).
    GetDerivedKey = 0x1,
    /// Extended report with certificate table (`SNP_GET_EXT_REPORT`).
    GetExtReport = 0x2,
    _Undefined,
}

const SEV: Group = Group::new(b'S');

/// Fetch a standard SNP attestation report.
pub const SNP_GET_REPORT: Ioctl<WriteRead, &GuestRequest<ReportReq, ReportRsp>> =
    unsafe { SEV.write_read(GuestIoctl::GetReport as u8) };

/// Derive a guest key from VCEK or VMRK root material.
pub const SNP_GET_DERIVED_KEY: Ioctl<WriteRead, &GuestRequest<DerivedKeyReq, DerivedKeyRsp>> =
    unsafe { SEV.write_read(GuestIoctl::GetDerivedKey as u8) };

/// Fetch an attestation report plus an optional firmware certificate table.
pub const SNP_GET_EXT_REPORT: Ioctl<WriteRead, &GuestRequest<ExtReportReq, ReportRsp>> =
    unsafe { SEV.write_read(GuestIoctl::GetExtReport as u8) };

/// Envelope passed to every `/dev/sev-guest` ioctl.
///
/// Mirrors the Linux kernel's guest-request structure: carries pointers to the
/// request payload, response buffer, and a firmware error word populated by the
/// kernel on failure.
#[repr(C)]
pub struct GuestRequest<'a, 'b, Req, Rsp> {
    /// Message version number (must be non-zero).
    pub message_version: u32,
    /// Guest-virtual address of the request structure.
    pub request_data: u64,
    /// Guest-virtual address of the response structure.
    pub response_data: u64,
    /// Firmware error word written by the kernel on failure.
    pub fw_err: u64,

    _phantom_req: PhantomData<&'a mut Req>,
    _phantom_rsp: PhantomData<&'b mut Rsp>,
}

impl<'a, 'b, Req, Rsp> GuestRequest<'a, 'b, Req, Rsp> {
    /// Build a guest ioctl envelope from request and response buffers.
    ///
    /// `ver` defaults to `1` when `None`. The kernel reads/writes the structures
    /// at the addresses derived from `req` and `rsp`.
    pub fn new(ver: Option<u32>, req: &'a mut Req, rsp: &'b mut Rsp) -> Self {
        Self {
            message_version: ver.unwrap_or(1),
            request_data: req as *mut Req as u64,
            response_data: rsp as *mut Rsp as u64,
            fw_err: Default::default(),
            _phantom_req: PhantomData,
            _phantom_rsp: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_request_new() {
        let mut req = ReportReq::default();
        let mut rsp = ReportRsp::default();

        // Test with explicit version
        let guest_req = GuestRequest::new(Some(2), &mut req, &mut rsp);
        assert_eq!(guest_req.message_version, 2);
        assert_ne!(guest_req.request_data, 0);
        assert_ne!(guest_req.response_data, 0);
        assert_eq!(guest_req.fw_err, 0);

        // Test with default version
        let guest_req = GuestRequest::new(None, &mut req, &mut rsp);
        assert_eq!(guest_req.message_version, 1);
        assert_ne!(guest_req.request_data, 0);
        assert_ne!(guest_req.response_data, 0);
        assert_eq!(guest_req.fw_err, 0);
    }

    #[test]
    fn test_guest_ioctl_values() {
        assert_eq!(GuestIoctl::GetReport as u8, 0x0);
        assert_eq!(GuestIoctl::GetDerivedKey as u8, 0x1);
        assert_eq!(GuestIoctl::GetExtReport as u8, 0x2);
    }
}
