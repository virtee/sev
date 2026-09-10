// SPDX-License-Identifier: Apache-2.0

//! SNP guest attester: collect evidence from `/dev/sev-guest`.
//!
//! This module implements the RATS **Attester** role for SEV-SNP guests. A
//! guest VM uses [`Firmware`] to request attestation reports, extended reports
//! (with certificate tables), and derived keys from the AMD Secure Processor
//! (ASP). The bytes returned here are **evidence** — they are not verified in
//! this module.
//!
//! # Attestation flow
//!
//! ```text
//!  Guest VM                         Verifier (separate role)
//!  ─────────                        ────────────────────────
//!  Firmware::open()
//!       │
//!       ├─ get_report() ──► raw report bytes ──► Report::from_bytes()
//!       │                                          │
//!       ├─ get_ext_report() ──► report + cert table ──► Chain::from_cert_table_*()
//!       │                                          │
//!       └─ get_derived_key() ──► 32-byte key      └─► Verifiable + ReportBody
//! ```
//!
//! Typical downstream steps (see [`crate::attestation::verifier`] and
//! [`crate::attestation::evidence::snp`]):
//!
//! 1. Frame the report with [`Report::from_bytes`](crate::attestation::evidence::snp::Report::from_bytes).
//! 2. Obtain endorsement material from [`crate::attestation::endorser::snp`]
//!    (built-in roots, host-exported cert table, or files).
//! 3. Verify the report signature and parse fields with
//!    [`ReportBody::try_from`](crate::attestation::evidence::snp::ReportBody).
//!
//! # API summary
//!
//! | Method | Purpose |
//! |--------|---------|
//! | [`Firmware::open`] | Open `/dev/sev-guest` |
//! | [`Firmware::get_report`] | Standard 1184-byte attestation report |
//! | [`Firmware::get_ext_report`] | Report plus optional firmware certificate table |
//! | [`Firmware::get_derived_key`] | Guest-derived key (vCPU-secrets, etc.) |
//!
//! # Platform requirements
//!
//! - Linux guest with the `sev-guest` kernel module and `/dev/sev-guest` device node
//! - `attester` and `snp` crate features enabled
//! - Guest must be running under an SNP-enabled hypervisor
//!
//! # Errors
//!
//! Ioctl failures are mapped to [`UserApiError`](crate::error::UserApiError),
//! distinguishing VMM errors (upper 32 bits of firmware status) from ASP/firmware
//! errors (lower 32 bits). Non-zero response status fields also surface as
//! [`FirmwareError`](crate::error::FirmwareError).

use crate::error::*;
use crate::types::snp::{platform::CertTableEntry, DerivedKey};

#[cfg(target_os = "linux")]
use crate::firmware::guest::{cert_table::KernelCertTableEntry, ioctl::*, types::*};

#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};

/// Map the firmware error word from a guest ioctl into a user-facing error.
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

/// SNP guest firmware handle backed by the `/dev/sev-guest` device node.
///
/// Primary attester interface for SEV-SNP guests. Obtain with [`Self::open`],
/// then call [`Self::get_report`], [`Self::get_ext_report`], or
/// [`Self::get_derived_key`].
///
/// For verification and appraisal of returned bytes, use
/// [`crate::attestation::verifier`].
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Firmware(File);

#[cfg(target_os = "linux")]
impl Firmware {
    /// Open a handle to the SEV-SNP guest device at `/dev/sev-guest`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the device node is missing or cannot be
    /// opened (for example, the guest is not SNP-enabled or the driver is not loaded).
    pub fn open() -> std::io::Result<Self> {
        Ok(Self(OpenOptions::new().read(true).open("/dev/sev-guest")?))
    }

    /// Request a standard attestation report from the ASP.
    ///
    /// Returns the raw 1184-byte report blob. Parse it with
    /// [`Report::from_bytes`](crate::attestation::evidence::snp::Report::from_bytes);
    /// do not interpret body fields before verification.
    ///
    /// # Arguments
    ///
    /// * `message_version` — guest–firmware protocol version; defaults to `1`.
    /// * `data` — optional 64-byte guest-provided report data (defaults to zeros).
    /// * `vmpl` — Virtual Machine Privilege Level; defaults to `0`.
    ///
    /// # Returns
    ///
    /// Raw attestation report bytes (`Report::REPORT_LEN` = 1184).
    ///
    /// # Errors
    ///
    /// [`UserApiError`](crate::error::UserApiError) on ioctl failure, firmware
    /// status errors, or invalid request parameters.
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

        if response.status != 0 {
            Err(FirmwareError::from(response.status))?
        }

        Ok(response.report.to_vec())
    }

    /// Request an extended attestation report and optional certificate table.
    ///
    /// Same report semantics as [`Self::get_report`], but the firmware may also
    /// return a certificate table ([`CertTableEntry`](crate::types::snp::platform::CertTableEntry))
    /// suitable for building a [`Chain`](crate::attestation::endorser::snp::Chain)
    /// via [`Chain::from_cert_table_der`](crate::attestation::endorser::snp::Chain::from_cert_table_der)
    /// or [`Chain::from_cert_table_pem`](crate::attestation::endorser::snp::Chain::from_cert_table_pem).
    ///
    /// # Arguments
    ///
    /// Same as [`Self::get_report`].
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - raw attestation report bytes
    /// - `Some(cert_table)` when the platform returned certificates, or `None`
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_report`]. Certificate table parse failures return
    /// [`CertError`](crate::error::CertError).
    ///
    /// # Notes
    ///
    /// Retries automatically when the VMM reports
    /// [`VmmError::InvalidCertificatePageLength`](crate::error::VmmError::InvalidCertificatePageLength)
    /// (pre-5.19 kernel quirk).
    pub fn get_ext_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<(Vec<u8>, Option<Vec<CertTableEntry>>), UserApiError> {
        let report_request = ReportReq::new(data, vmpl)?;

        let mut report_response = ReportRsp::default();
        let mut certificate_bytes: Vec<u8>;
        let mut ext_report_request = ExtReportReq::new(&report_request);

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

        if report_response.status != 0 {
            Err(FirmwareError::from(report_response.status))?
        }

        if ext_report_request.certs_len == 0 {
            return Ok((report_response.report.to_vec(), None));
        }

        let mut certificates: Vec<CertTableEntry>;

        unsafe {
            let entries = (ext_report_request.certs_address as *mut KernelCertTableEntry)
                .as_mut()
                .ok_or(CertError::EmptyCertBuffer)?;
            certificates = KernelCertTableEntry::parse_table(entries)?;
            certificates.sort();
        }

        Ok((report_response.report.to_vec(), Some(certificates)))
    }

    /// Request a guest-derived key from the ASP.
    ///
    /// Derives a 32-byte key bound to guest context (for example, vCPU secrets
    /// or launch mitigation). Populate [`DerivedKey`] with the fields documented
    /// in the SNP guest firmware ABI before calling.
    ///
    /// # Arguments
    ///
    /// * `message_version` — protocol version; defaults to `2`. Versions `>= 2`
    ///   require [`DerivedKey::launch_mit_vector`] to be set.
    /// * `derived_key_request` — key derivation parameters (guest field select,
    ///   VMPL, root key select, etc.).
    ///
    /// # Returns
    ///
    /// 32-byte derived key material.
    ///
    /// # Errors
    ///
    /// [`UserApiError::IOError`](crate::error::UserApiError::IOError) with
    /// [`InvalidInput`](std::io::ErrorKind::InvalidInput) when message version
    /// `>= 2` is used without a launch mitigation vector. Other failures map
    /// through [`UserApiError`](crate::error::UserApiError) like
    /// [`Self::get_report`].
    pub fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        mut derived_key_request: DerivedKey,
    ) -> Result<[u8; 32], UserApiError> {
        let message_version = if message_version.is_some() {
            message_version
        } else {
            Some(2)
        };

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
        let raw_error = RawFwError(1);
        let error = map_fw_err(raw_error);
        assert!(matches!(error, UserApiError::FirmwareError(_)));

        let raw_error = RawFwError(0x100000000u64);
        let error = map_fw_err(raw_error);
        assert!(matches!(error, UserApiError::VmmError(_)));

        let raw_error = RawFwError(0x0u64);
        let error = map_fw_err(raw_error);
        assert!(matches!(
            error,
            UserApiError::FirmwareError(FirmwareError::UnknownSevError(0))
        ));
    }
}
