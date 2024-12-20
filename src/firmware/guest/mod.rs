// SPDX-License-Identifier: Apache-2.0

//! # Guest Owner
//!
//! The Guest owner is a tenant of a virtualization provider. They may have
//! one or more guest confidential virtual-machines (VM) or containers which
//! may be deployed in a Platform Owner's environment..

mod types;

pub use types::*;

use crate::error::*;

#[cfg(target_os = "linux")]
use crate::firmware::{
    host::CertTableEntry,
    linux::{
        guest::{ioctl::*, types::*},
        host as HostFFI,
    },
};

use std::convert::TryFrom;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};

/// Checks the `fw_err` field on the [GuestRequest](crate::firmware::linux::guest::ioctl::GuestRequest) structure
/// to make sure that no errors were encountered by the VMM or the AMD
/// Secure Processor.
fn map_fw_err(raw_error: RawFwError) -> UserApiError {
    let (upper, lower): (u32, u32) = raw_error.into();

    if upper != 0 {
        return VmmError::from(upper).into();
    }

    if lower != 0 {
        return FirmwareError::from(lower).into();
    }

    FirmwareError::UnknownSevError(lower).into()
}

/// A handle to the SEV-SNP guest device.
#[cfg(target_os = "linux")]
pub struct Firmware(File);

#[cfg(target_os = "linux")]
impl Firmware {
    /// Generate a new file handle to the SEV guest platform via `/dev/sev-guest`.
    ///
    /// # Example:
    ///
    /// ```ignore
    /// let mut firmware: Firmware = firmware.open().unwrap();
    /// ```
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).open("/dev/sev-guest")?,
        ))
    }

    /// Requests an attestation report from the AMD Secure Processor. The `message_version` will default
    /// to `1` if `None` is specified.
    ///
    /// # Example:
    ///
    /// ```ignore
    /// // Create some unique data we wish to see included in our report. This could be a SHA, a public key, etc.
    /// let unique_data: [u8; 64] = [
    ///     65, 77, 68, 32, 105, 115, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 97, 119,
    ///     101, 115, 111, 109, 101, 33, 32, 87, 101, 32, 109, 97, 107, 101, 32, 116, 104, 101, 32,
    ///     98, 101, 115, 116, 32, 67, 80, 85, 115, 33, 32, 65, 77, 68, 32, 82, 111, 99, 107, 115,
    ///     33, 33, 33, 33, 33, 33,
    /// ];
    ///
    /// // Create a message version (OPTIONAL)
    /// let msg_ver: u8 = 1;
    ///
    /// // Open a connection to the AMD Secure Processor.
    /// let mut fw: Firmware = Firmware::open().unwrap();
    ///
    /// // Set the VMPL level (OPTIONAL).
    /// let vmpl = 1;
    ///
    /// // Request the attestation report with our unique_data.
    /// let attestation_report: AttestationReport = fw.get_report(Some(msg_ver), Some(unique_data), Some(vmpl)).unwrap();
    /// ```
    pub fn get_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<AttestationReport, UserApiError> {
        let mut input = ReportReq::new(data, vmpl)?;
        let mut response = ReportRsp::default();

        let mut request: GuestRequest<ReportReq, ReportRsp> =
            GuestRequest::new(message_version, &mut input, &mut response);

        SNP_GET_REPORT
            .ioctl(&mut self.0, &mut request)
            .map_err(|_| map_fw_err(request.fw_err.into()))?;

        // Make sure response status is successful
        if response.status != 0 {
            Err(FirmwareError::from(response.status))?
        }

        let raw_report = response.report.as_array();

        Ok(AttestationReport::try_from(raw_report.as_slice())?)
    }

    /// Request an extended attestation report from the AMD Secure Processor.
    /// The `message_version` will default to `1` if `None` is specified.
    ///
    /// Behaves the same as [get_report](crate::firmware::guest::Firmware::get_report).
    pub fn get_ext_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<(AttestationReport, Option<Vec<CertTableEntry>>), UserApiError> {
        let report_request = ReportReq::new(data, vmpl)?;

        let mut report_response = ReportRsp::default();

        // Define a buffer to store the certificates in.
        let mut certificate_bytes: Vec<u8>;

        // Due to the complex buffer allocation, we will take the ReportReq
        // provided by the caller, and create an extended report request object
        // for them.
        let mut ext_report_request = ExtReportReq::new(&report_request);

        // Construct the object needed to perform the IOCTL request.
        // *NOTE:* This is __important__ because a fw_err value which matches
        // [InvalidCertificatePageLength](crate::error::VmmError::InvalidCertificatePageLength) will indicate the buffer was not large
        // enough.
        let mut guest_request: GuestRequest<ExtReportReq, ReportRsp> = GuestRequest::new(
            message_version,
            &mut ext_report_request,
            &mut report_response,
        );

        // KEEP for Kernels before 47894e0f (5.19), as userspace broke at that hash.
        if SNP_GET_EXT_REPORT
            .ioctl(&mut self.0, &mut guest_request)
            .is_err()
        {
            match guest_request.fw_err.into() {
                // The kernel patch by pgonda@google.com in kernel hash 47894e0f
                // changed the ioctl return to succeed instead of returning an
                // error when encountering an invalid certificate length. This was
                // done to keep the cryptography safe, so we will now just check
                // the guest_request.fw_err for a new value.
                //
                // Check to see if the buffer needs to be resized. If it does, the
                // we need to resize the buffer to the correct size, and
                // re-request for the certificates.
                VmmError::InvalidCertificatePageLength => {
                    certificate_bytes = vec![0u8; ext_report_request.certs_len as usize];
                    ext_report_request.certs_address = certificate_bytes.as_mut_ptr() as u64;
                    let mut guest_request_retry: GuestRequest<ExtReportReq, ReportRsp> =
                        GuestRequest::new(
                            message_version,
                            &mut ext_report_request,
                            &mut report_response,
                        );
                    SNP_GET_EXT_REPORT
                        .ioctl(&mut self.0, &mut guest_request_retry)
                        .map_err(|_| map_fw_err(guest_request_retry.fw_err.into()))?;
                }
                _ => Err(map_fw_err(guest_request.fw_err.into()))?,
            }
        }

        // Make sure response status is successful
        if report_response.status != 0 {
            Err(FirmwareError::from(report_response.status))?
        }

        let raw_report = report_response.report.as_array();

        let report = AttestationReport::try_from(raw_report.as_slice())?;

        if ext_report_request.certs_len == 0 {
            return Ok((report, None));
        }

        let mut certificates: Vec<CertTableEntry>;

        unsafe {
            let entries = (ext_report_request.certs_address as *mut HostFFI::types::CertTableEntry)
                .as_mut()
                .ok_or(CertError::EmptyCertBuffer)?;
            certificates = HostFFI::types::CertTableEntry::parse_table(entries)?;
            certificates.sort();
        }

        // Return both the Attestation Report, as well as the Cert Table.
        Ok((report, Some(certificates)))
    }

    /// Fetches a derived key from the AMD Secure Processor. The `message_version` will default to `1` if `None` is specified.
    ///
    /// # Example:
    /// ```ignore
    /// let request: DerivedKey = DerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0);
    ///
    /// let mut fw: Firmware = Firmware::open().unwrap();
    /// let derived_key: DerivedKeyRsp = fw.get_derived_key(None, request).unwrap();
    /// ```
    pub fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        derived_key_request: DerivedKey,
    ) -> Result<[u8; 32], UserApiError> {
        let mut ffi_derived_key_request: DerivedKeyReq = derived_key_request.into();
        let mut ffi_derived_key_response: DerivedKeyRsp = Default::default();

        {
            let mut request: GuestRequest<DerivedKeyReq, DerivedKeyRsp> = GuestRequest::new(
                message_version,
                &mut ffi_derived_key_request,
                &mut ffi_derived_key_response,
            );

            SNP_GET_DERIVED_KEY
                .ioctl(&mut self.0, &mut request)
                .map_err(|_| map_fw_err(request.fw_err.into()))?;
        }

        // Make sure response status is successfuls
        if ffi_derived_key_response.status != 0 {
            Err(FirmwareError::from(ffi_derived_key_response.status))?
        }

        Ok(ffi_derived_key_response.key)
    }
}
