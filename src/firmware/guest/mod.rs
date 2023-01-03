// SPDX-License-Identifier: Apache-2.0

//! Guest Owner Rust-friendly API interfaces.

/// Rust-friendly types returned by FFI wrapping APIs.
pub mod types;

use std::fs::{File, OpenOptions};

use self::types::*;

use super::host::types::{CertTableEntry, Error, Indeterminate};
use super::linux::host::types::CertTableEntry as FFICertTableEntry;
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

    /// Request an extended attestation report from the PSP
    ///
    /// # Arguments
    ///
    /// * `message_version` - (Optional) Used for the SnpGuestRequest, specifies the message version number defaults to 1.
    /// * `report_request` - an SnpReportReq object with its associated data.
    ///
    pub fn snp_get_ext_report(
        &mut self,
        message_version: Option<u8>,
        report_request: SnpReportReq,
    ) -> Result<(AttestationReport, Vec<CertTableEntry>), Indeterminate<Error>> {
        // Due to the complex buffer allocation, we will take the SnpReportReq
        // provided by the caller, and create an extended report request object
        // for them.
        let ext_report_request: SnpExtReportReq = SnpExtReportReq::new(report_request);

        // Create an object for the PSP to store the response content in.
        let ext_report_response: SnpReportRsp = Default::default();

        let mut certificates: Vec<CertTableEntry> = vec![];

        // Construct the needed object needed to perform the IOCTL request.
        // *NOTE:* This is __important__ because a fw_err value which matches
        // [`INVALID_CERT_BUFFER`] will indicate the buffer was not large
        // enough.
        let mut guest_request: SnpGuestRequest<SnpExtReportReq, SnpReportRsp> =
            SnpGuestRequest::new(message_version, &ext_report_request, &ext_report_response);

        let ioctl_return = SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request);

        if let Err(ioctl_error) = ioctl_return {
            // Any errors other than INVALID_CERT_BUFFER are unexpected
            // IoErrors, and should be returned.
            if guest_request.fw_err != INVALID_CERT_BUFFER {
                return Err(Indeterminate::Known(Error::IoError(ioctl_error)));
            }

            // If we have reached this point, our error is due to an
            // invalide certificate buffer size.
            //
            // Create a copy of the original (IOCTL modified) request,
            // and modify the certificate buffer to the size provided
            // from the PSP (extend_buffer()), and update the guest_request.
            let mut new_request: SnpExtReportReq = ext_report_request;
            new_request.extend_buffer();
            guest_request.request_data = &mut new_request as *mut SnpExtReportReq as u64;

            // Now that the buffer has been extended to the correct size, we
            // should be able to expect a successfull ioctl call the second
            // time around.
            SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request)?;
        }

        // If an FFI Certificate Table is returned, we want to parse that table
        // into a Rust-friendly structure to be returned. Calling `to_uapi()` will
        // do that for us.
        unsafe {
            if let Some(linux_cert_table) =
                (ext_report_request.certs_address as *mut FFICertTableEntry).as_mut()
            {
                certificates =
                    FFICertTableEntry::parse_table(linux_cert_table as *mut FFICertTableEntry);
            }
        }

        // Return both the Attestation Report, as well as the Cert Table.
        Ok((ext_report_response.report, certificates))
    }
}
