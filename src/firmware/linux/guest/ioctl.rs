// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crate::firmware::linux::guest::types::{
    SnpDerivedKeyReq, SnpDerivedKeyRsp, SnpExtReportReq, SnpReportReq, SnpReportRsp,
};
use iocuddle::{Group, Ioctl, WriteRead};

pub enum SnpGuestIoctl {
    SnpGetReport = 0x0,
    SnpGetDerivedKey = 0x1,
    SnpGetExtReport = 0x2,
    _Undefined,
}

const SEV: Group = Group::new(b'S');

pub const SNP_GET_REPORT: Ioctl<WriteRead, &SnpGuestRequest<SnpReportReq, SnpReportRsp>> =
    unsafe { SEV.write_read(SnpGuestIoctl::SnpGetReport as u8) };

pub const SNP_GET_DERIVED_KEY: Ioctl<
    WriteRead,
    &SnpGuestRequest<SnpDerivedKeyReq, SnpDerivedKeyRsp>,
> = unsafe { SEV.write_read(SnpGuestIoctl::SnpGetDerivedKey as u8) };

pub const SNP_GET_EXT_REPORT: Ioctl<WriteRead, &SnpGuestRequest<SnpExtReportReq, SnpReportRsp>> =
    unsafe { SEV.write_read(SnpGuestIoctl::SnpGetExtReport as u8) };

/// The default structure used for making requests to the PSP as a guest owner.
#[repr(C)]
pub struct SnpGuestRequest<'a, 'b, Req, Rsp> {
    /// Message version number (must be non-zero)
    pub message_version: u8,
    /// Request structure address.
    pub request_data: u64,
    /// Response structure address.
    pub response_data: u64,
    /// Firmware error address.
    pub fw_err: u64,

    _phantom_req: PhantomData<&'a mut Req>,
    _phantom_rsp: PhantomData<&'b mut Rsp>,
}

impl<'a, 'b, Req, Rsp> SnpGuestRequest<'a, 'b, Req, Rsp> {
    /// Creates a new request from the addresses provided.
    ///
    /// # Arguments:
    ///
    /// * `ver` - Option<u8> - Version of the message.
    /// * `req` - &Req - The reference a Request object.
    /// * `rsp` - &Rsp - The reference a Response object.
    pub fn new(ver: Option<u8>, req: &'a mut Req, rsp: &'b mut Rsp) -> Self {
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
