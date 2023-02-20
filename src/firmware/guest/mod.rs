// SPDX-License-Identifier: Apache-2.0

//! Guest Owner Rust-friendly API interfaces.

/// Rust-friendly types returned by FFI wrapping APIs.
pub mod types;

use std::fs::{File, OpenOptions};

use self::types::*;

use super::host::types::{CertTableEntry, Error, Indeterminate, UserApiError};
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
        mut report_request: SnpReportReq,
    ) -> Result<AttestationReport, Indeterminate<Error>> {
        let mut report_response: SnpReportRsp = SnpReportRsp::default();

        SNP_GET_REPORT.ioctl(
            &mut self.0,
            &mut SnpGuestRequest::new(message_version, &mut report_request, &mut report_response),
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
        let mut derived_key_response: SnpDerivedKeyRsp = SnpDerivedKeyRsp::default();

        SNP_GET_DERIVED_KEY.ioctl(
            &mut self.0,
            &mut SnpGuestRequest::new(
                message_version,
                &mut SnpDerivedKeyReq::from_uapi(derived_key_request),
                &mut derived_key_response,
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
    ) -> Result<(AttestationReport, Vec<CertTableEntry>), UserApiError> {
        // Define a buffer to store the certificates in.
        let mut certificate_bytes: Vec<u8>;

        // Due to the complex buffer allocation, we will take the SnpReportReq
        // provided by the caller, and create an extended report request object
        // for them.
        let mut ext_report_request: SnpExtReportReq = SnpExtReportReq::new(&report_request);

        // Create an object for the PSP to store the response content in.
        let mut ext_report_response: SnpReportRsp = Default::default();

        // Construct the object needed to perform the IOCTL request.
        // *NOTE:* This is __important__ because a fw_err value which matches
        // [`INVALID_CERT_BUFFER`] will indicate the buffer was not large
        // enough.
        let mut guest_request: SnpGuestRequest<SnpExtReportReq, SnpReportRsp> =
            SnpGuestRequest::new(
                message_version,
                &mut ext_report_request,
                &mut ext_report_response,
            );

        // KEEP for Kernels before 47894e0f (5.19), as userspace broke at that hash.
        if let Err(ioctl_error) = SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request) {
            if guest_request.fw_err != INVALID_CERT_BUFFER {
                return Err(ioctl_error.into());
            }
        }

        // The kernel patch by pgonda@google.com in kernel hash 47894e0f
        // changed the ioctl return to succeed instead of returning an
        // error when encountering an invalid certificate length. This was
        // done to keep the cryptography safe, so we will now just check
        // the guest_request.fw_err for a new value.
        //
        // Check to see if the buffer needs to be resized. If it does, the
        // we need to resize the buffer to the correct size, and
        // re-request for the certificates.
        if guest_request.fw_err == INVALID_CERT_BUFFER {
            certificate_bytes = vec![0u8; ext_report_request.certs_len as usize];
            ext_report_request.certs_address = certificate_bytes.as_mut_ptr() as u64;
            let mut guest_request_retry: SnpGuestRequest<SnpExtReportReq, SnpReportRsp> =
                SnpGuestRequest::new(
                    message_version,
                    &mut ext_report_request,
                    &mut ext_report_response,
                );
            SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request_retry)?;
        } else if guest_request.fw_err != 0 {
            // This shouldn't be possible, but if it happens, throw an error.
            return Err(UserApiError::FirmwareError(Error::InvalidConfig));
        }

        // If an entries are returned, we want to parse that table into a Rust-friendly structure
        // to be returned. Calling `parse_table()` will do that for us.
        let mut certificates: Vec<CertTableEntry> = vec![];

        unsafe {
            if let Some(linux_cert_table) =
                (ext_report_request.certs_address as *mut FFICertTableEntry).as_mut()
            {
                certificates =
                    FFICertTableEntry::parse_table(linux_cert_table as *mut FFICertTableEntry)?
            }
        }

        // Return both the Attestation Report, as well as the Cert Table.
        Ok((ext_report_response.report, certificates))
    }
}
