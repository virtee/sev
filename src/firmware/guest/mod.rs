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
    linux::guest::{ioctl::*, types::*},
};

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
#[derive(Debug)]
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
    /// let msg_ver: u32 = 1;
    ///
    /// // Open a connection to the AMD Secure Processor.
    /// let mut fw: Firmware = Firmware::open().unwrap();
    ///
    /// // Set the VMPL level (OPTIONAL).
    /// let vmpl = 1;
    ///
    /// // Request the raw attestation report with our unique_data.
    /// let report_bytes: Vec<u8> = fw.get_report(Some(msg_ver), Some(unique_data), Some(vmpl)).unwrap();
    /// ```
    pub fn get_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<Vec<u8>, UserApiError> {
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

        Ok(response.report.to_vec())
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
    ) -> Result<(Vec<u8>, Option<Vec<CertTableEntry>>), UserApiError> {
        let report_request = ReportReq::new(data, vmpl)?;

        let mut report_response = ReportRsp::default();

        // Define a buffer to store the certificates in.
        let mut certificate_bytes: Vec<u8> = vec![];

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

        let result = SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request);

        // Depending on the kernel version, a certificate buffer that is too
        // small either fails the ioctl or returns success. Both cases set
        // fw_err, and this code checks it in either case.
        match guest_request.fw_err.into() {
            // Resize the buffer to the length the kernel asked for and
            // request the certificates again.
            VmmError::InvalidCertificatePageLength => {
                certificate_bytes = vec![0u8; ext_report_request.certs_len as usize];
                ext_report_request.certs_address = certificate_bytes.as_mut_ptr() as u64;
                let mut guest_request_retry: GuestRequest<ExtReportReq, ReportRsp> =
                    GuestRequest::new(
                        message_version,
                        &mut ext_report_request,
                        &mut report_response,
                    );
                let retry_result = SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request_retry);
                if retry_result.is_err() || guest_request_retry.fw_err != 0 {
                    Err(map_fw_err(guest_request_retry.fw_err.into()))?
                }
            }
            _ if result.is_err() || guest_request.fw_err != 0 => {
                Err(map_fw_err(guest_request.fw_err.into()))?
            }
            _ => {}
        }

        // Make sure response status is successful
        if report_response.status != 0 {
            Err(FirmwareError::from(report_response.status))?
        }

        if ext_report_request.certs_len == 0 {
            return Ok((report_response.report.to_vec(), None));
        }

        // The kernel writes certificates only into a buffer that this
        // function allocated. Without one, certs_address still holds the
        // u64::MAX placeholder from ExtReportReq::new.
        if certificate_bytes.is_empty() {
            Err(CertError::EmptyCertBuffer)?
        }

        let mut certificates = CertTableEntry::vec_bytes_to_cert_table(&mut certificate_bytes)?;
        certificates.sort();

        // Return both the Attestation Report, as well as the Cert Table.
        Ok((report_response.report.to_vec(), Some(certificates)))
    }

    /// Fetches a derived key from the AMD Secure Processor. The `message_version` will default to `2` if `None` is specified.
    ///
    /// # Example:
    /// ```ignore
    /// let request: DerivedKey = DerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0, None);
    ///
    /// let mut fw: Firmware = Firmware::open().unwrap();
    /// let derived_key: DerivedKeyRsp = fw.get_derived_key(1, request).unwrap();
    /// ```
    pub fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        mut derived_key_request: DerivedKey,
    ) -> Result<[u8; 32], UserApiError> {
        // Defaulting to 2 instead of the regular 1 introduced in FW 1.58
        let message_version = if message_version.is_some() {
            message_version
        } else {
            Some(2)
        };

        // Check if the launch mitigation vector is provided for message version >= 2
        if let Some(version) = message_version {
            if version >= 2 {
                if derived_key_request.launch_mit_vector.is_none() {
                    use std::io;

                    return Err(UserApiError::IOError(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Launch Mitigation Vector must be provided for message version >= 2",
                    )));
                }
            } else {
                // Set launch_vector to None for message requests version 1.
                derived_key_request.launch_mit_vector = None;
            }
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firmware_error_mapping() {
        let raw_error = RawFwError(1); // Lower byte error
        let error = map_fw_err(raw_error);
        assert!(matches!(error, UserApiError::FirmwareError(_)));

        let raw_error = RawFwError(0x100000000u64); // Upper byte error
        let error = map_fw_err(raw_error);
        assert!(matches!(error, UserApiError::VmmError(_)));

        let raw_error = RawFwError(0x0u64); // lower byte error
        let error = map_fw_err(raw_error);
        assert!(matches!(
            error,
            UserApiError::FirmwareError(FirmwareError::UnknownSevError(0))
        ));
    }
}
