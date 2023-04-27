// SPDX-License-Identifier: Apache-2.0

//! # Guest Owner
//!
//! The Guest owner is a tenant of a virtualization provider. They may have
//! one or more guest confidential virtual-machines (VM) or containers which
//! may be deployed in a Platform Owner's environment..

mod types;

pub use types::*;

use crate::{
    error::*,
    firmware::{
        host::CertTableEntry,
        linux::{
            guest::{ioctl::*, types::*},
            host as HostFFI,
        },
    },
};

use std::fs::{File, OpenOptions};

// Disabled until upstream Linux kernel is patched.
//
// /// Checks the `fw_err` field on the [`GuestRequest`] structure
// /// to make sure that no errors were encountered by the VMM or the AMD
// /// Secure Processor.
// fn check_fw_err(raw_error: RawFwError) -> Result<(), UserApiError> {
//     if raw_error != 0.into() {
//         let (upper, lower): (u32, u32) = raw_error.into();
//
//         if upper != 0 {
//             return Err(VmmError::from(upper).into());
//         }
//
//         if lower != 0 {
//             match lower.into() {
//                 Indeterminate::Known(error) => return Err(error.into()),
//                 Indeterminate::Unknown => return Err(UserApiError::Unknown),
//             }
//         }
//     }
//     Ok(())
// }

/// A handle to the SEV-SNP guest device.
pub struct Firmware(File);

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
    /// // Set the VMPL level.
    /// let vmpl = 1;
    ///
    /// // Request the attestation report with our unique_data.
    /// let attestation_report: AttestationReport = fw.get_report(Some(msg_ver), Some(unique_data), vmpl).unwrap();
    /// ```
    pub fn get_report(
        &mut self,
        message_version: Option<u8>,
        data: Option<[u8; 64]>,
        vmpl: u32,
    ) -> Result<AttestationReport, UserApiError> {
        let mut input = ReportReq::new(data, vmpl)?;
        let mut response = ReportRsp::default();

        let mut request: GuestRequest<ReportReq, ReportRsp> =
            GuestRequest::new(message_version, &mut input, &mut response);

        SNP_GET_REPORT.ioctl(&mut self.0, &mut request)?;

        // Disabled until upstream Linux kernel is patched.
        // check_fw_err(request.fw_err.into())?;

        Ok(response.report)
    }

    /// Request an extended attestation report from the AMD Secure Processor.
    /// The `message_version` will default to `1` if `None` is specified.
    ///
    /// Behaves the same as [`get_report`](crate::firmware::guest::Firmware::get_report).
    pub fn get_ext_report(
        &mut self,
        message_version: Option<u8>,
        data: Option<[u8; 64]>,
        vmpl: u32,
    ) -> Result<(AttestationReport, Vec<CertTableEntry>), UserApiError> {
        let mut report_request = ReportReq::new(data, vmpl)?;
        let mut report_response = ReportRsp::default();

        // Define a buffer to store the certificates in.
        let mut certificate_bytes: Vec<u8>;

        // Due to the complex buffer allocation, we will take the ReportReq
        // provided by the caller, and create an extended report request object
        // for them.
        let mut ext_report_request = ExtReportReq::new(&mut report_request);

        // Construct the object needed to perform the IOCTL request.
        // *NOTE:* This is __important__ because a fw_err value which matches
        // [`INVALID_CERT_BUFFER`] will indicate the buffer was not large
        // enough.
        let mut guest_request: GuestRequest<ExtReportReq, ReportRsp> = GuestRequest::new(
            message_version,
            &mut ext_report_request,
            &mut report_response,
        );

        // KEEP for Kernels before 47894e0f (5.19), as userspace broke at that hash.
        if let Err(ioctl_error) = SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request) {
            match guest_request.fw_err.into() {
                VmmError::InvalidCertificatePageLength => (),
                VmmError::RateLimitRetryRequest => {
                    return Err(VmmError::RateLimitRetryRequest.into())
                }
                _ => return Err(ioctl_error.into()),
            }

            // Eventually the code below will be moved back into this scope.
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
        if VmmError::InvalidCertificatePageLength == guest_request.fw_err.into() {
            certificate_bytes = vec![0u8; ext_report_request.certs_len as usize];
            ext_report_request.certs_address = certificate_bytes.as_mut_ptr() as u64;
            let mut guest_request_retry: GuestRequest<ExtReportReq, ReportRsp> = GuestRequest::new(
                message_version,
                &mut ext_report_request,
                &mut report_response,
            );
            SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request_retry)?;
        } else if guest_request.fw_err != 0 {
            // This shouldn't be possible, but if it happens, throw an error.
            return Err(UserApiError::FirmwareError(Error::InvalidConfig));
        }

        let certificates: Vec<CertTableEntry>;

        unsafe {
            let entries = (ext_report_request.certs_address as *mut HostFFI::types::CertTableEntry)
                .as_mut()
                .ok_or(CertError::EmptyCertBuffer)?;
            certificates = HostFFI::types::CertTableEntry::parse_table(entries)?;
        }

        // Return both the Attestation Report, as well as the Cert Table.
        Ok((report_response.report, certificates))
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
        message_version: Option<u8>,
        derived_key_request: DerivedKey,
    ) -> Result<[u8; 32], UserApiError> {
        let mut ffi_derived_key_request: DerivedKeyReq = derived_key_request.into();
        let mut ffi_derived_key_response: DerivedKeyRsp = Default::default();

        let mut request: GuestRequest<DerivedKeyReq, DerivedKeyRsp> = GuestRequest::new(
            message_version,
            &mut ffi_derived_key_request,
            &mut ffi_derived_key_response,
        );

        SNP_GET_DERIVED_KEY.ioctl(&mut self.0, &mut request)?;

        // Disabled until upstream Linux kernel is patched.
        // check_fw_err(request.fw_err.into())?;

        Ok(ffi_derived_key_response.key)
    }
}
