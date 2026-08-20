// SPDX-License-Identifier: Apache-2.0

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};
use std::{
    convert::TryFrom,
    fmt::Display,
    io::{Read, Write},
};

/// Identifies the firmware-defined format version of an SEV-SNP attestation report.
///
/// `ReportVariant` corresponds to the *report layout version* as emitted by
/// platform firmware. The variant determines:
///
/// - Which fields are present in the report body
/// - How certain fields are interpreted (e.g. TCB layout)
/// - How platform generation is inferred
///
/// This enum is intentionally **narrow and explicit**: only variants currently
/// understood by the library are represented. Any unknown or future report
/// versions will be rejected during decoding.
///
/// ---
///
/// # Version Semantics
///
/// | Variant | Firmware Versions | Notes |
/// |--------:|-------------------|-------|
/// | `V2` | 2 | Pre-CPUID reports. Platform generation is inferred from the CHIP_ID field. |
/// | `V3` | 3, 4 | Introduces CPUID fields used for platform identification. |
/// | `V5` | 5 | Adds mitigation vector fields and additional reserved regions. |
///
/// Firmware version values `3` and `4` are treated equivalently and both map to
/// [`ReportVariant::V3`], as they share an identical report layout.
///
/// ---
///
/// # Security Considerations
///
/// `ReportVariant` only describes the *format* of the report. It does **not**
/// imply that the report is authentic or trustworthy.
///
/// A parsed `ReportVariant` must not be used as a trust signal on its own.
/// Authenticity is only established after successful cryptographic verification
/// of the report signature.
///
/// ---
///
/// # Parsing and Validation
///
/// `ReportVariant` is decoded from the first 4 bytes of the report body and
/// validated during parsing. Unsupported or unknown version values will cause
/// parsing to fail with an error.
///
/// This ensures forward compatibility is explicit and prevents accidental
/// acceptance of report formats the library does not understand.
///
/// ---
///
/// # Correct Usage
///
/// `ReportVariant` is primarily consumed internally during report parsing to
/// drive generation inference and conditional field handling.
///
/// Consumers should not attempt to construct `ReportVariant` values manually
/// from untrusted inputs; instead, rely on decoding via [`ReportBody`] or
/// verified [`Report`] processing.
///
/// ---
///
/// # Example
///
/// ```ignore
/// let variant = ReportVariant::decode(&mut reader, ())?;
///
/// match variant {
///     ReportVariant::V2 => { /* CHIP_ID-based inference */ }
///     ReportVariant::V3 => { /* CPUID-based inference */ }
///     ReportVariant::V5 => { /* mitigation vector fields present */ }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ReportVariant {
    /// Version 2 of the attestation report format.
    ///
    /// This variant predates CPUID-based platform identification. Platform
    /// generation is inferred heuristically from the CHIP_ID field.
    V2 = 2,

    /// Version 3 (and firmware version 4) of the attestation report format.
    ///
    /// Introduces CPUID family, model, and stepping fields, enabling explicit
    /// platform identification. Firmware versions `3` and `4` share the same
    /// report layout and are represented by this variant.
    V3 = 3,

    /// Version 5 of the attestation report format.
    ///
    /// Extends the V3 layout with mitigation vector fields and additional
    /// reserved regions. Used by newer firmware revisions.
    V5 = 5,
}

impl TryFrom<u32> for ReportVariant {
    type Error = std::io::Error;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            2 => Ok(ReportVariant::V2),
            3 | 4 => Ok(ReportVariant::V3),
            5 => Ok(ReportVariant::V5),
            unknown_variant => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported report variant: {}", unknown_variant),
            )),
        }
    }
}

impl Encoder<()> for ReportVariant {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        match self {
            ReportVariant::V2 => writer.write_bytes(2u32, ())?,
            ReportVariant::V3 => writer.write_bytes(3u32, ())?,
            ReportVariant::V5 => writer.write_bytes(5u32, ())?,
        };
        Ok(())
    }
}

impl Decoder<()> for ReportVariant {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let version: u32 = reader.read_bytes()?;
        Self::try_from(version)
    }
}

impl ByteParser<()> for ReportVariant {
    type Bytes = [u8; 4];
    const EXPECTED_LEN: Option<usize> = Some(4);
}

impl Display for ReportVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportVariant::V2 => write!(f, "V2"),
            ReportVariant::V3 => write!(f, "V3"),
            ReportVariant::V5 => write!(f, "V5"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_extraction() {
        let raw_v2 = [2, 0, 0, 0]; // Version 2
        let version = u32::from_le_bytes([raw_v2[0], raw_v2[1], raw_v2[2], raw_v2[3]]);
        assert_eq!(version, 2);

        let raw_v3 = [3, 0, 0, 0]; // Version 3
        let version = u32::from_le_bytes([raw_v3[0], raw_v3[1], raw_v3[2], raw_v3[3]]);
        assert_eq!(version, 3);
    }

    #[test]
    fn test_report_variant_tryfrom() {
        assert_eq!(ReportVariant::try_from(2).unwrap(), ReportVariant::V2);
        assert_eq!(ReportVariant::try_from(3).unwrap(), ReportVariant::V3);
        assert_eq!(ReportVariant::try_from(4).unwrap(), ReportVariant::V3);
        assert_eq!(ReportVariant::try_from(5).unwrap(), ReportVariant::V5);
        assert!(ReportVariant::try_from(99).is_err());
    }
}
