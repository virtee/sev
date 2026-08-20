// SPDX-License-Identifier: Apache-2.0

use crate::{attestation::evidence::snp::SignatureAlgorithm, parser::Decoder};

/// A zero-copy view of a raw SEV-SNP attestation report.
///
/// This type splits the report into borrowed views:
/// - `algorithm`: the signature algorithm identifier (decoded from body offset `0x34`)
/// - `body`: the bytes covered by the report signature
/// - `signature`: the firmware-provided signature bytes
///
/// `Report` does **not** imply authenticity or integrity. It is just a view over
/// untrusted bytes. Consumers should verify the signature (via
/// [`crate::attestation::verifier`]) before interpreting any fields from the
/// body.
///
/// This design supports a two-phase workflow:
/// 1. Parse the outer framing with [`Report::from_bytes`] to locate the signed
///    body, signature, and signature algorithm.
/// 2. Verify the signature over `body`, then parse the verified body into
///    [`ReportBody`](super::ReportBody) for typed access.
///
/// # Notes
///
/// - `Report` borrows from the input buffer (`'a`), so the input bytes must
///   outlive the `Report`.
/// - The offsets used by [`Report::from_bytes`] assume the current fixed
///   firmware report layout and size ([`Report::REPORT_LEN`] bytes).
#[derive(Debug, Clone, Copy)]
pub struct Report<'a> {
    /// Signature algorithm used to sign this report (from body offset `0x34`).
    pub algorithm: SignatureAlgorithm,
    /// Bytes covered by the report signature (`0x00..0x2A0`).
    pub body: &'a [u8],
    /// Firmware-provided signature bytes (`0x2A0..0x4A0`).
    pub signature: &'a [u8],
}

impl<'a> Report<'a> {
    /// Total attestation report size in bytes (1184).
    pub const REPORT_LEN: usize = 0x4A0; // 1184
    const BODY_LEN: usize = 0x2A0; // bytes 0x000..=0x29F
    const SIG_OFF: usize = 0x2A0;
    const SIG_LEN: usize = 0x200; // bytes 0x2A0..=0x49F
    const SIG_ALGO_OFF: usize = 0x34;
    const SIG_ALGO_LEN: usize = 0x4;
    /// Parse a raw attestation report into body, signature, and algorithm views.
    ///
    /// This function performs **framing only**:
    /// - validates the total report length ([`Self::REPORT_LEN`])
    /// - decodes [`SignatureAlgorithm`] from body offset `0x34`
    /// - returns borrowed slices for the signed body and signature
    ///
    /// It does **not** verify the signature or validate reserved fields.
    /// Use [`ReportBody::try_from`](super::ReportBody) (with a certificate or
    /// chain) via [`crate::attestation::verifier`] to obtain a verified
    /// [`ReportBody`](super::ReportBody).
    pub fn from_bytes(report: &'a [u8]) -> std::io::Result<Self> {
        if report.len() != Self::REPORT_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Bad report length",
            ));
        };

        let algorithm = SignatureAlgorithm::decode(
            &mut &report[Self::SIG_ALGO_OFF..Self::SIG_ALGO_OFF + Self::SIG_ALGO_LEN],
            (),
        )?;

        Ok(Self {
            algorithm,
            body: &report[..Self::BODY_LEN],
            signature: &report[Self::SIG_OFF..Self::SIG_OFF + Self::SIG_LEN],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::ReportBody;
    use std::ops::Range;

    const CHIP_ID_RANGE: Range<usize> = 0x1A0..0x1E0;

    #[test]
    fn test_report_copy() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];

        // Setting sig algo
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();
        let copy = report;

        assert_eq!(report.body.as_ptr(), copy.body.as_ptr());
        assert_eq!(report.body.len(), copy.body.len());
        assert_eq!(report.signature.as_ptr(), copy.signature.as_ptr());
        assert_eq!(report.signature.len(), copy.signature.len());
    }

    #[test]
    fn test_report_from_bytes_ok() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2
        bytes[CHIP_ID_RANGE.start] = 1; // unmask chip id

        // signature algorithm
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        // policy u64 LE at 0x08..0x10
        let policy_raw = 1u64 << 17; // RMB1 bit
        bytes[0x08..0x10].copy_from_slice(&policy_raw.to_le_bytes());

        let report = Report::from_bytes(bytes.as_slice());
        assert!(report.is_ok());

        // Also ensure the body can be parsed
        let report = report.unwrap();
        assert!(ReportBody::from_bytes(report.body).is_ok());
    }

    #[test]
    fn test_report_from_bytes_rejects_bad_len() {
        let bytes = vec![0u8; Report::REPORT_LEN - 1];
        let err = Report::from_bytes(&bytes).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_report_from_bytes_splits_body_and_signature() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];

        // signature algorithm
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let r = Report::from_bytes(&bytes).unwrap();

        assert_eq!(r.body.len(), 0x2a0);
        assert_eq!(r.signature.len(), 0x49f + 1 - 0x2a0);
        assert_eq!(r.body.as_ptr(), bytes.as_ptr());
        assert_eq!(
            r.signature.as_ptr() as usize - bytes.as_ptr() as usize,
            0x2a0
        );
    }
}
