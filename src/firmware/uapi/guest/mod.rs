// SPDX-License-Identifier: Apache-2.0

//! Guest Owner Rust-friendly API interfaces.

/// Rust-friendly types returned by FFI wrapping APIs.
pub mod types;

use std::fs::{File, OpenOptions};

use self::types::*;

use super::host::types::{Error, Indeterminate};
use crate::firmware::linux::guest::ioctl::*;

/// A handle to the SEV, SEV-ES, or SEV-SNP platform.
pub struct Firmware(File);

impl Firmware {
    /// Generate a new file handle to the SEV guest platform.
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sev-guest")?,
        ))
    }

    /// Request an attestation report from the PSP
    ///
    /// # Arguments
    ///
    /// * `message_version` - (Optional) Used for the SnpGuestRequest, specifies the message version number defaults to 1.
    /// * `report_request` - an SnpReportReq object with its associated data for requesting the attestation report.
    ///
    pub fn snp_get_report(
        &mut self,
        message_version: Option<u8>,
        report_request: SnpReportReq,
    ) -> Result<AttestationReport, Indeterminate<Error>> {
        let report_response: SnpReportRsp = SnpReportRsp::default();

        SNP_GET_REPORT.ioctl(
            &mut self.0,
            &mut SnpGuestRequest::new(message_version, &report_request, &report_response),
        )?;

        Ok(report_response.report)
    }

    /// Fetches a derived key from the PSP
    ///
    /// # Arguments
    ///
    /// * `message_version` - (Optional) Used for the SnpGuestRequest, specifies the message version number defaults to 1.
    /// * `derived_key_request` - an SnpDerivedKeyReq object with its associated data for generating a derived key.
    ///
    pub fn snp_get_derived_key(
        &mut self,
        message_version: Option<u8>,
        derived_key_request: SnpDerivedKey,
    ) -> Result<SnpDerivedKeyRsp, Indeterminate<Error>> {
        let derived_key_response: SnpDerivedKeyRsp = SnpDerivedKeyRsp::default();

        SNP_GET_DERIVED_KEY.ioctl(
            &mut self.0,
            &mut SnpGuestRequest::new(
                message_version,
                &SnpDerivedKeyReq::from_uapi(derived_key_request),
                &derived_key_response,
            ),
        )?;

        Ok(derived_key_response)
    }

    /// Request an attestation report from the PSP
    ///
    /// # Arguments
    ///
    /// * `message_version` - (Optional) Used for the SnpGuestRequest, specifies the message version number defaults to 1.
    /// * `ext_report_request` - an SnpExtReportReq object with its associated data for requesting the extended attestation report.
    ///
    pub fn snp_get_ext_report(
        &mut self,
        message_version: Option<u8>,
        ext_report_request: SnpExtReportReq,
    ) -> Result<SnpReportRsp, Indeterminate<Error>> {
        let ext_report_response: SnpReportRsp = SnpReportRsp::default();

        SNP_GET_EXT_REPORT.ioctl(
            &mut self.0,
            &mut SnpGuestRequest::new(
                message_version,
                &SnpExtReportReq {
                    data: ext_report_request.data,
                    certs_address: ext_report_request.certs_address,
                    certs_len: ext_report_request.certs_len,
                },
                &ext_report_response,
            ),
        )?;

        Ok(ext_report_response)
    }
}
