use crate::firmware::linux::guest::types::{
    SnpDerivedKeyReq, SnpDerivedKeyRsp, SnpExtReportReq, SnpExtReportRsp, SnpGuestRequest,
    SnpReportReq, SnpReportRsp,
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

pub const SNP_GET_EXT_REPORT: Ioctl<WriteRead, &SnpGuestRequest<SnpExtReportReq, SnpExtReportRsp>> =
    unsafe { SEV.write_read(SnpGuestIoctl::SnpGetExtReport as u8) };
