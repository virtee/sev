// SPDX-License-Identifier: Apache-2.0

use crate::firmware::linux::guest::types::{
    DerivedKeyReq, DerivedKeyRsp, ExtReportReq, ReportReq, ReportRsp,
};

use std::marker::PhantomData;

use iocuddle::{Group, Ioctl, WriteRead};

pub enum GuestIoctl {
    GetReport = 0x0,
    GetDerivedKey = 0x1,
    GetExtReport = 0x2,
    _Undefined,
}

const SEV: Group = Group::new(b'S');

pub const SNP_GET_REPORT: Ioctl<WriteRead, &GuestRequest<ReportReq, ReportRsp>> =
    unsafe { SEV.write_read(GuestIoctl::GetReport as u8) };

pub const SNP_GET_DERIVED_KEY: Ioctl<WriteRead, &GuestRequest<DerivedKeyReq, DerivedKeyRsp>> =
    unsafe { SEV.write_read(GuestIoctl::GetDerivedKey as u8) };

pub const SNP_GET_EXT_REPORT: Ioctl<WriteRead, &GuestRequest<ExtReportReq, ReportRsp>> =
    unsafe { SEV.write_read(GuestIoctl::GetExtReport as u8) };

/// The default structure used for making requests to the PSP as a guest owner.
#[repr(C)]
pub struct GuestRequest<'a, 'b, Req, Rsp> {
    /// Message version number (must be non-zero)
    pub message_version: u32,
    /// Request structure address.
    pub request_data: u64,
    /// Response structure address.
    pub response_data: u64,
    /// Firmware error address.
    pub fw_err: u64,

    _phantom_req: PhantomData<&'a mut Req>,
    _phantom_rsp: PhantomData<&'b mut Rsp>,
}

impl<'a, 'b, Req, Rsp> GuestRequest<'a, 'b, Req, Rsp> {
    /// Creates a new request from the addresses provided.
    ///
    /// # Arguments:
    ///
    /// * `ver` - Option<u32> - Version of the message.
    /// * `req` - &Req - The reference a Request object.
    /// * `rsp` - &Rsp - The reference a Response object.
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
