// SPDX-License-Identifier: Apache-2.0

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use crate::certs::snp::{Certificate, Chain, Verifiable};

use crate::{
    certs::snp::signature::SignatureAlgorithm,
    firmware::host::TcbVersion,
    parser::{ByteParser, Decoder, Encoder},
    util::{
        hexline::HexLine,
        parser_helper::{validate_reserved, ReadExt, WriteExt},
    },
    Generation,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_big_array::BigArray;

use std::{
    convert::TryFrom,
    fmt::Display,
    io::{Read, Write},
};

use bitfield::bitfield;

const ATT_REP_FW_LEN: usize = 1184;

/// Structure of required data for fetching the derived key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DerivedKey {
    /// Selects the root key to derive the key from.
    /// 0: Indicates VCEK.
    /// 1: Indicates VMRK.
    root_key_select: u32,

    /// Reserved, must be zero
    _reserved_0: u32,

    /// What data will be mixed into the derived key.
    pub guest_field_select: GuestFieldSelect,

    /// The VMPL to mix into the derived key. Must be greater than or equal
    /// to the current VMPL.
    pub vmpl: u32,

    /// The guest SVN to mix into the key. Must not exceed the guest SVN
    /// provided at launch in the ID block.
    pub guest_svn: u32,

    /// The TCB version to mix into the derived key. Must not
    /// exceed CommittedTcb.
    pub tcb_version: u64,

    /// The mitigation vector value to mix into the derived key.
    /// Specific bit settings corresponding to mitigations required for Guest operation.
    pub launch_mit_vector: Option<u64>,
}

impl DerivedKey {
    /// Create a new instance for requesting an DerivedKey.
    pub fn new(
        root_key_select: bool,
        guest_field_select: GuestFieldSelect,
        vmpl: u32,
        guest_svn: u32,
        tcb_version: u64,
        launch_mit_vector: Option<u64>,
    ) -> Self {
        Self {
            root_key_select: u32::from(root_key_select),
            _reserved_0: Default::default(),
            guest_field_select,
            vmpl,
            guest_svn,
            tcb_version,
            launch_mit_vector,
        }
    }

    /// Obtain a copy of the root key select value (Private Field)
    pub fn get_root_key_select(&self) -> u32 {
        self.root_key_select
    }
}

bitfield! {
    /// Data which will be mixed into the derived key.
    ///
    /// | Bit(s) | Name | Description |
    /// |--------|------|-------------|
    /// |0|GUEST_POLICY|Indicates that the guest policy will be mixed into the key.|
    /// |1|IMAGE_ID|Indicates that the image ID of the guest will be mixed into the key.|
    /// |2|FAMILY_ID|Indicates the family ID of the guest will be mixed into the key.|
    /// |3|MEASUREMENT|Indicates the measurement of the guest during launch will be mixed into the key.|
    /// |4|GUEST_SVN|Indicates that the guest-provided SVN will be mixed into the key.|
    /// |5|TCB_VERSION|Indicates that the guest-provided TCB_VERSION will be mixed into the key.|
    /// |6|LAUNCH_MIT_VECTOR|Indicates that the guest-provided LAUNCH_MIT_VECTOR will be mixed into the key.|
    /// |63:7|\-|Reserved. Must be zero.|
    #[repr(C)]
    #[derive(Default, Copy, Clone,PartialEq, Eq, PartialOrd, Ord)]
    pub struct GuestFieldSelect(u64);
    impl Debug;
    /// Check/Set guest policy inclusion in derived key.
    pub get_guest_policy, set_guest_policy: 0;
    /// Check/Set image id inclusion in derived key.
    pub get_image_id, set_image_id: 1;
    /// Check/Set family id inclusion in derived key.
    pub get_family_id, set_family_id: 2;
    /// Check/Set measurement inclusion in derived key.
    pub get_measurement, set_measurement: 3;
    /// Check/Set svn inclusion in derived key.
    pub get_svn, set_svn: 4;
    /// Check/Set tcb version inclusion in derived key.
    pub get_tcb_version, set_tcb_version: 5;
     /// Indicates that the guest-provied LAUNCH_MIT_VECTOR will be mixed into the key.
    pub get_launch_mit_vector, set_launch_mit_vector: 6;
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// A semver formatted version.
pub struct Version {
    /// Major Version
    pub major: u8,
    /// Minor Version
    pub minor: u8,
    /// Build Version
    pub build: u8,
}

impl Version {
    /// Create a new version.
    pub fn new(major: u8, minor: u8, build: u8) -> Self {
        Self {
            major,
            minor,
            build,
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

impl Encoder<()> for Version {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.build, ())?;
        writer.write_bytes(self.minor, ())?;
        writer.write_bytes(self.major, ())?;
        Ok(())
    }
}

impl Decoder<()> for Version {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let build = reader.read_bytes()?;
        let minor = reader.read_bytes()?;
        let major = reader.read_bytes()?;
        Ok(Self {
            major,
            minor,
            build,
        })
    }
}

impl ByteParser<()> for Version {
    type Bytes = [u8; 3];
    const EXPECTED_LEN: Option<usize> = Some(3);
}

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
    V3 = 3 | 4,

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

/// A zero-copy view of a raw SEV-SNP attestation report.
///
/// This type splits the report into two byte slices:
/// - `body`: the bytes covered by the report signature
/// - `signature`: the firmware-provided signature bytes
///
/// `Report` does **not** imply authenticity or integrity. It is just a view over
/// untrusted bytes. Consumers should verify the signature (using [`Verifiable`])
/// before interpreting any fields from the body.
///
/// This design supports a two-phase workflow:
/// 1) Parse the outer framing to locate the signed body and signature.
/// 2) Verify the signature over `body`, then parse the verified body into
///    [`ReportBody`] for typed access.
///
/// # Notes
/// - `Report` borrows from the input buffer (`'a`), so the input bytes must
///   outlive the `Report`.
/// - The offsets used by [`Report::from_bytes`] assume the current fixed
///   firmware report layout and size (1184 bytes).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct Report<'a> {
    /// The signature algorithm used to sign the attestation report
    pub algorithm: SignatureAlgorithm,
    /// The bytes covered by the report signature (bytes 0x00 to 0x2A0).
    pub body: &'a [u8],
    /// The signature bytes (0x2A0..0x4A0).
    pub signature: &'a [u8],
}

impl<'a> Report<'a> {
    const REPORT_LEN: usize = 0x4A0; // 1184
    const BODY_LEN: usize = 0x2A0; // bytes 0x000..=0x29F
    const SIG_OFF: usize = 0x2A0;
    const SIG_LEN: usize = 0x200; // bytes 0x2A0..=0x49F
    /// Parse a raw attestation report into body and signature slices.
    ///
    /// This function performs **framing only**:
    /// - validates the total report length
    /// - returns borrowed slices for the signed body and signature
    ///
    /// It does **not** verify the signature or validate reserved fields.
    /// Use [`ReportBody::try_from`] (with a certificate or chain) to obtain a
    /// verified [`ReportBody`].
    pub fn from_bytes(report: &'a [u8]) -> std::io::Result<Self> {
        if report.len() != Self::REPORT_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad report length",
            ));
        };

        let algorithm = SignatureAlgorithm::decode(&mut &report[0x34..0x38], ())?;

        Ok(Self {
            algorithm,
            body: &report[..Self::BODY_LEN],
            signature: &report[Self::SIG_OFF..Self::SIG_OFF + Self::SIG_LEN],
        })
    }
}

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
impl Verifiable for (&Certificate, &Report<'_>) {
    type Output = ();

    fn verify(self) -> Result<Self::Output, std::io::Error> {
        let (vek, report) = self;

        let algo = report.algorithm;

        algo.verify(report.body, report.signature, vek)
    }
}

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
impl Verifiable for (&Chain, &Report<'_>) {
    type Output = ();

    fn verify(self) -> Result<(), std::io::Error> {
        let (chain, report) = self;
        let vek = chain.verify()?;
        (vek, report).verify()
    }
}

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
/// Verifies `report` with `vek` and returns a parsed [`ReportBody`].
impl<'a> TryFrom<(&Report<'a>, &Certificate)> for ReportBody<'a> {
    type Error = std::io::Error;

    fn try_from((report, vek): (&Report<'a>, &Certificate)) -> Result<Self, Self::Error> {
        (vek, report).verify()?;
        ReportBody::from_bytes(report.body)
    }
}

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
/// Verifies `report` with `chain` and returns a parsed [`ReportBody`].
///
/// This is the **recommended** way to obtain a `ReportBody`, because it
/// enforces signature verification before parsing typed fields.
impl<'a> TryFrom<(&Report<'a>, &Chain)> for ReportBody<'a> {
    type Error = std::io::Error;

    fn try_from((report, chain): (&Report<'a>, &Chain)) -> Result<Self, Self::Error> {
        (chain, report).verify()?;
        ReportBody::from_bytes(report.body)
    }
}

/// A zero-copy view of the attestation report body.
/// All byte-arrayfields are borrowed from the original report body slice, so the input bytes must outlive this struct.
///
/// This struct contains fully typed and parsed fields from the attestation report body.
/// All fields are parsed to their final types at [`ReportBody::from_bytes`] time, including
/// TCB version parsing with generation-aware layout selection.
///
/// The correct method to generate [`ReportBody`] is from a [`Report`]:
/// ```ignore
/// let report = Report::from_bytes(&raw_bytes);
/// let body = ReportBody::try_from((&report, &vek))
/// ```
///
/// This will verify the signature and body of the report before parsing it into fully typed fields.
///
/// [`ReportBody::from_bytes`] can be used to parse the body from raw bytes, but this should be done for debugging purposes.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReportBody<'a> {
    /// Version number of this attestation report.
    pub version: ReportVariant,

    /// Guest Security Version Number (SVN).
    pub guest_svn: u32,

    /// Guest policy governing hypervisor restrictions.
    pub policy: GuestPolicy,

    /// Family ID provided at launch (128 bits).
    pub family_id: &'a [u8; 16],

    /// Image ID provided at launch (128 bits).
    pub image_id: &'a [u8; 16],

    /// Virtual Machine Privilege Level (VMPL) of the attestation request.
    pub vmpl: u32,

    /// Signature algorithm used to sign this report.
    pub sig_algo: SignatureAlgorithm,

    /// Current TCB (Trusted Computing Base) version, parsed for the inferred generation.
    pub current_tcb: TcbVersion,

    /// Platform information flags.
    pub plat_info: PlatformInfo,

    /// Key and signing information.
    pub key_info: KeyInfo,

    /// Guest-provided data (512 bits).
    pub report_data: &'a [u8; 64],

    /// Launch measurement (SHA-384).
    pub measurement: &'a [u8; 48],

    /// Host-provided data (256 bits).
    pub host_data: &'a [u8; 32],

    /// SHA-384 digest of the ID public key.
    pub id_key_digest: &'a [u8; 48],

    /// SHA-384 digest of the Author public key.
    pub author_key_digest: &'a [u8; 48],

    /// Report ID of this guest (256 bits).
    pub report_id: &'a [u8; 32],

    /// Report ID of this guest's migration agent (256 bits).
    pub report_id_ma: &'a [u8; 32],

    /// Reported TCB version used to derive the VCEK, parsed for the inferred generation.
    pub reported_tcb: TcbVersion,

    /// CPUID Family ID - present in report version 3+.
    pub cpuid_fam_id: Option<u8>,

    /// CPUID Model ID - present in report version 3+.
    pub cpuid_mod_id: Option<u8>,

    /// CPUID Stepping - present in report version 3+.
    pub cpuid_step: Option<u8>,

    /// Chip identifier (512 bits). Zero if MaskChipId was set during launch.
    pub chip_id: &'a [u8; 64],

    /// Committed TCB version, parsed for the inferred generation.
    pub committed_tcb: TcbVersion,

    /// Current firmware version (major.minor.build).
    pub current: Version,

    /// Committed firmware version (major.minor.build).
    pub committed: Version,

    /// Launch TCB version, parsed for the inferred generation.
    pub launch_tcb: TcbVersion,

    /// Launch mitigation vector - present in report version 5+.
    pub launch_mit_vector: Option<u64>,

    /// Current mitigation vector - present in report version 5+.
    pub current_mit_vector: Option<u64>,
}

impl<'a> ReportBody<'a> {
    /// The expected length of the report body (bytes 0x00 to 0x2A0).
    pub const BODY_LEN: usize = 0x2A0;

    /// Parses a raw attestation report body into a typed [`ReportBody`].
    ///
    /// Security Warning
    ///
    /// This function **does not perform any cryptographic verification**.
    /// It only parses the provided byte slice according to the SEV-SNP
    /// attestation report layout.
    ///
    /// Calling this method directly means the caller is responsible for
    /// ensuring that the input bytes are authentic and have not been
    /// tampered with.
    ///
    /// ---
    ///
    /// # Correct Usage
    ///
    /// The **recommended and correct way** to obtain a [`ReportBody`] is via
    /// the `TryFrom` implementation that verifies the report signature first:
    ///
    /// ```ignore
    /// let report = Report::from_bytes(&raw_bytes)?;
    /// let body = ReportBody::try_from((&report, &certificate))?;
    /// ```
    ///
    /// or
    ///
    /// ```ignore
    /// let report = Report::from_bytes(&raw_bytes)?;
    /// let body = ReportBody::try_from((&report, &chain))?;
    /// ```
    ///
    /// These conversion paths:
    ///
    /// 1. Verify the report signature using the provided VEK or certificate chain.
    /// 2. Only after successful verification, parse the signed body bytes
    ///    into a typed [`ReportBody`].
    ///
    /// This ensures that parsed fields such as TCB versions, policy flags,
    /// measurements, and identifiers are cryptographically authenticated.
    ///
    /// ---
    ///
    /// # Intended Use of `from_bytes`
    ///
    /// This method exists primarily for:
    ///
    /// - Internal parsing after successful verification
    /// - Debugging and inspection of raw report bytes
    /// - Unit tests that validate layout and field decoding logic
    ///
    /// It should **not** be used in security-sensitive paths where the
    /// authenticity of the report matters.
    ///
    /// ---
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The body length is incorrect
    /// - The report version is unsupported
    /// - Reserved fields are non-zero
    /// - The chip ID is masked (for V2 reports)
    /// - Generation inference fails
    ///
    /// This function validates structural correctness, but **not**
    /// authenticity.
    ///
    pub fn from_bytes(body: &'a [u8]) -> Result<Self, std::io::Error> {
        if body.len() < Self::BODY_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Report body too short: expected {} bytes, got {}",
                    Self::BODY_LEN,
                    body.len()
                ),
            ));
        }

        // Parse version to determine variant and generation
        let version = ReportVariant::decode(&mut &body[0x00..0x04], ())?;

        // Infer generation from chip_id (V2) or CPUID fields (V3+)
        let generation = if version >= ReportVariant::V3 {
            // V3+ uses CPUID fields
            let family = body[0x188];
            let model = body[0x189];
            Generation::identify_cpu(family, model)?
        } else {
            // V2 uses chip_id heuristic
            let chip_id_bytes = &body[0x1A0..0x1E0];
            if chip_id_bytes == &[0u8; 64][..] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Chip ID is masked",
                ));
            } else if chip_id_bytes[8..] == [0u8; 56] {
                // Turin-like: first 8 bytes non-zero, rest zero
                Generation::Turin
            } else {
                // Genoa-like: full 64 bytes used
                Generation::Genoa
            }
        };

        let guest_svn = u32::decode(&mut &body[0x04..0x08], ())?;

        let policy = GuestPolicy(u64::decode(&mut &body[0x08..0x10], ())?);

        let family_id: &'a [u8; 16] = <&[u8; 16]>::try_from(&body[0x10..0x20])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let image_id: &'a [u8; 16] = <&[u8; 16]>::try_from(&body[0x20..0x30])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let vmpl = u32::decode(&mut &body[0x30..0x34], ())?;

        let sig_algo = SignatureAlgorithm::decode(&mut &body[0x34..0x38], ())?;

        let current_tcb = TcbVersion::decode(&mut &body[0x38..0x40], generation)?;

        let plat_info = PlatformInfo::decode(&mut &body[0x40..0x48], ())?;

        let key_info = KeyInfo::decode(&mut &body[0x48..0x4C], ())?;

        // Reserved 0x4C - 0x51
        validate_reserved(&body[0x4C..0x50])?;

        let report_data: &'a [u8; 64] = <&[u8; 64]>::try_from(&body[0x50..0x90])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let measurement: &'a [u8; 48] = <&[u8; 48]>::try_from(&body[0x90..0xC0])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let host_data: &'a [u8; 32] = <&[u8; 32]>::try_from(&body[0xC0..0xE0])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let id_key_digest: &'a [u8; 48] = <&[u8; 48]>::try_from(&body[0xE0..0x110])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let author_key_digest: &'a [u8; 48] = <&[u8; 48]>::try_from(&body[0x110..0x140])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let report_id: &'a [u8; 32] = <&[u8; 32]>::try_from(&body[0x140..0x160])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let report_id_ma: &'a [u8; 32] = <&[u8; 32]>::try_from(&body[0x160..0x180])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let reported_tcb = TcbVersion::decode(&mut &body[0x180..0x188], generation)?;

        // Parse CPUID fields (V3+) or extract raw values
        let (cpuid_fam_id, cpuid_mod_id, cpuid_step) = if version as u32 >= 3 {
            // Reserved 0x18B - 0x19F
            validate_reserved(&body[0x18B..0x1A0])?;
            (Some(body[0x188]), Some(body[0x189]), Some(body[0x18A]))
        } else {
            // Reserved 0x188 - 0x19F
            validate_reserved(&body[0x188..0x1A0])?;
            (None, None, None)
        };

        let chip_id: &'a [u8; 64] = <&[u8; 64]>::try_from(&body[0x1A0..0x1E0])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let committed_tcb = TcbVersion::decode(&mut &body[0x1E0..0x1E8], generation)?;

        // Parse current and committed firmware versions
        let current = Version {
            build: body[0x1E8],
            minor: body[0x1E9],
            major: body[0x1EA],
        };

        // Reserved 0x1EB
        validate_reserved(&body[0x1EB..0x1EC])?;

        let committed = Version {
            build: body[0x1EC],
            minor: body[0x1ED],
            major: body[0x1EE],
        };

        // Reserved 0x1EF
        validate_reserved(&body[0x1EF..0x1F0])?;

        let launch_tcb = TcbVersion::decode(&mut &body[0x1F0..0x1F8], generation)?;

        // Parse mitigation vector fields (V5+)
        let (launch_mit_vector, current_mit_vector) = if version as u32 >= 5 {
            // Reserved 0x208 - 0x29F
            validate_reserved(&body[0x208..0x2A0])?;
            let launch = u64::decode(&mut &body[0x1F8..0x200], ())?;
            let current = u64::decode(&mut &body[0x200..0x208], ())?;
            (Some(launch), Some(current))
        } else {
            // Reserved 1F8 - 0x29F
            validate_reserved(&body[0x1F8..0x2A0])?;
            (None, None)
        };

        Ok(Self {
            version,
            guest_svn,
            policy,
            family_id,
            image_id,
            vmpl,
            sig_algo,
            current_tcb,
            plat_info,
            key_info,
            report_data,
            measurement,
            host_data,
            id_key_digest,
            author_key_digest,
            report_id,
            report_id_ma,
            reported_tcb,
            cpuid_fam_id,
            cpuid_mod_id,
            cpuid_step,
            chip_id,
            committed_tcb,
            current,
            committed,
            launch_tcb,
            launch_mit_vector,
            current_mit_vector,
        })
    }
}

impl ByteParser<()> for ReportBody<'_> {
    type Bytes = [u8; ATT_REP_FW_LEN];
    const EXPECTED_LEN: Option<usize> = Some(ATT_REP_FW_LEN);
}

impl Display for ReportBody<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"Attestation Report:

Version:                      {}

Guest SVN:                    {}

{}

Family ID:{}

Image ID:{}

VMPL:                         {}

Signature Algorithm:          {}

Current TCB:

{}

{}

{}

Report Data:{}

Measurement:{}

Host Data:{}

ID Key Digest:{}

Author Key Digest:{}

Report ID:{}

Report ID Migration Agent:{}

Reported TCB:

{}

CPUID Family ID:              {}

CPUID Model ID:               {}

CPUID Stepping:               {}

Chip ID:{}

Committed TCB:

{}

Current Version:              {}

Committed Version:            {}

Launch TCB:

{}

Launch Mitigation Vector:     {}

Current Mitigation Vector:    {}
"#,
            self.version,
            self.guest_svn,
            self.policy,
            HexLine(self.family_id),
            HexLine(self.image_id),
            self.vmpl,
            self.sig_algo,
            self.current_tcb,
            self.plat_info,
            self.key_info,
            HexLine(self.report_data),
            HexLine(self.measurement),
            HexLine(self.host_data),
            HexLine(self.id_key_digest),
            HexLine(self.author_key_digest),
            HexLine(self.report_id),
            HexLine(self.report_id_ma),
            self.reported_tcb,
            self.cpuid_fam_id
                .map_or("None".to_string(), |fam| fam.to_string()),
            self.cpuid_mod_id
                .map_or("None".to_string(), |model| model.to_string()),
            self.cpuid_step
                .map_or("None".to_string(), |step| step.to_string()),
            HexLine(self.chip_id),
            self.committed_tcb,
            self.current,
            self.committed,
            self.launch_tcb,
            self.launch_mit_vector
                .map_or("None".to_string(), |lmv| lmv.to_string()),
            self.current_mit_vector
                .map_or("None".to_string(), |cmv| cmv.to_string()),
        )
    }
}

bitfield! {
    /// The firmware associates each guest with a guest policy that the guest owner provides. The
    /// firmware restricts what actions the hypervisor can take on this guest according to the guest policy.
    /// The policy also indicates the minimum firmware version to for the guest.
    ///
    /// The guest owner provides the guest policy to the firmware during launch. The firmware then binds
    /// the policy to the guest. The policy cannot be changed throughout the lifetime of the guest. The
    /// policy is also migrated with the guest and enforced by the destination platform firmware.
    ///
    /// | Bit(s) | Name              | Description                                                                                                        >
    /// |--------|-------------------|-------------------------------------------------------------------------------------------------------------------->
    /// | 7:0    | ABI_MINOR         | The minimum ABI minor version required for this guest to run.                                                      >
    /// | 15:8   | ABI_MAJOR         | The minimum ABI major version required for this guest to run.                                                      >
    /// | 16     | SMT               | 0: Host SMT usage is disallowed.<br>1: Host SMT usage is allowed.                                                  >
    /// | 17     | -                 | Reserved. Must be one.                                                                                             >
    /// | 18     | MIGRATE_MA        | 0: Association with a migration agent is disallowed.<br>1: Association with a migration agent is allowed           >
    /// | 19     | DEBUG             | 0: Debugging is disallowed.<br>1: Debugging is allowed.                                                            >
    /// | 20     | SINGLE_SOCKET     | 0: Guest can be activated on multiple sockets.<br>1: Guest can only be activated on one socket.                    >
    /// | 21     | CXL_ALLOW         | 0: CXL cannot be populated with devices or memory.<br>1: CXL can be populated with devices or memory.              >
    /// | 22     | MEM_AES_256_XTS   | 0: Allow either AES 128 XEX or AES 256 XTS for memory encryption.<br>1: Require AES 256 XTS for memory encryption. >
    /// | 23     | RAPL_DIS          | 0: Allow Running Average Power Limit (RAPL).<br>1: RAPL must be disabled.                                          >
    /// | 24     | CIPHERTEXT_HIDING | 0: Ciphertext hiding may be enabled or disabled.<br>1: Ciphertext hiding must be enabled.                          >
    /// | 25     | PAGE_SWAP_DISABLE | 0: Disable Guest access to SNP_PAGE_MOVE, SNP_SWAP_OUT and SNP_SWAP_IN commands.                                   >
    /// | 63:25  | -                 | Reserved. MBZ.                                                                                                     >
    ///
    #[repr(C)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
    pub struct GuestPolicy(u64);
    impl Debug;
    /// ABI_MINOR field: Indicates the minor API version.
    pub abi_minor, set_abi_minor: 7, 0;
    /// ABI_MAJOR field: Indicates the minor API version.
    pub abi_major, set_abi_major: 15, 8;
    /// SMT_ALLOWED field: Indicates the if SMT should be permitted.
    pub smt_allowed, set_smt_allowed: 16;
    /// MIGRATE_MA_ALLOWED field: Indicates the if migration is permitted with
    /// the migration agent.
    pub migrate_ma_allowed, set_migrate_ma_allowed: 18;
    /// DEBUG_ALLOWED field: Indicates the if debugging should is permitted.
    pub debug_allowed, set_debug_allowed: 19;
    /// SINGLE_SOCKET_REQUIRED field: Indicates the if a single socket is required.
    pub single_socket_required, set_single_socket_required: 20;
    /// CXL_ALLOW field: (1) can populate CXL devices/memory, (0) cannot populate CXL devices/memory
    pub cxl_allowed, set_cxl_allowed: 21;
    /// MEM_AES_256_XTS field: (1) require AES 256 XTS encryption, (0) allows either AES 128 XEX or AES 256 XTS encryption
    pub mem_aes_256_xts, set_mem_aes_256_xts: 22;
    /// RAPL_DIS field: (1) RAPL must be disabled, (0) allow RAPL
    pub rapl_dis, set_rapl_dis: 23;
    /// CIPHERTEXT_HIDING field: (1) ciphertext hiding must be enabled, (0) ciphertext hiding may be enabled/disabled
    pub ciphertext_hiding, set_ciphertext_hiding: 24;
    /// Guest policy to disable Guest access to SNP_PAGE_MOVE, SNP_SWAP_OUT, and SNP_SWAP_IN commands. If this policy
    /// option is selected to disable these Page Move commands, then these commands will return POLICY_FAILURE.
    /// 0: Do not disable Guest support for the commands.
    /// 1: Disable Guest support for the commands.
    ///
    /// **Since:** Report v5+
    pub page_swap_disabled, set_page_swap_disabled: 25;
}

impl Encoder<()> for GuestPolicy {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

impl Decoder<()> for GuestPolicy {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let policy = reader.read_bytes()?;
        Ok(Self(policy))
    }
}

impl ByteParser<()> for GuestPolicy {
    type Bytes = [u8; 8];
    const EXPECTED_LEN: Option<usize> = Some(8);
}

impl Display for GuestPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"Guest Policy (0x{:x}):
  ABI Major:     {}
  ABI Minor:     {}
  SMT Allowed:   {}
  Migrate MA:    {}
  Debug Allowed: {}
  Single Socket: {}
  CXL Allowed:   {}
  AEX 256 XTS:   {}
  RAPL Allowed:  {}
  Ciphertext hiding: {}
  Page Swap Disable: {}"#,
            self.0,
            self.abi_major(),
            self.abi_minor(),
            self.smt_allowed(),
            self.migrate_ma_allowed(),
            self.debug_allowed(),
            self.single_socket_required(),
            self.cxl_allowed(),
            self.mem_aes_256_xts(),
            self.rapl_dis(),
            self.ciphertext_hiding(),
            self.page_swap_disabled()
        )
    }
}

impl From<GuestPolicy> for u64 {
    fn from(value: GuestPolicy) -> Self {
        // Bit 17 of the guest policy is reserved and must always be set to 1.
        let reserved: u64 = 1 << 17;

        value.0 | reserved
    }
}

impl From<u64> for GuestPolicy {
    fn from(value: u64) -> Self {
        // Bit 17 of the guest policy is reserved and must always be set to 1.
        let reserved: u64 = 1 << 17;

        GuestPolicy(value | reserved)
    }
}

bitfield! {
    /// Version 2 PlatformInfo bitfield
    /// A structure with a bit-field unsigned 64 bit integer:
    /// Bit 0 representing the status of SMT enablement.
    /// Bit 1 representing the status of TSME enablement.
    /// Bit 2 indicates if ECC memory is used.
    /// Bit 3 indicates if RAPL is disabled.
    /// Bit 4 indicates if ciphertext hiding is enabled
    /// Bit 5 indicates that alias detection has completed since the last system reset and there are no aliasing addresses. Resets to 0.
    /// Bit 6 reserved
    /// Bit 7 indicates that SEV-TIO is enabled.
    /// Bits 8-63 are reserved.
    #[repr(C)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PlatformInfo(u64);
    impl Debug;
    /// Returns the bit state of SMT
    pub smt_enabled, _: 0;
    /// Returns the bit state of TSME.
    pub tsme_enabled, _: 1;
    /// Indicates that the platform is currently using ECC memory
    pub ecc_enabled, _: 2;
    /// Indicates that the RAPL feature is disabled
    pub rapl_disabled, _: 3;
    /// Indicates that ciphertext hiding is enabled
    pub ciphertext_hiding_enabled, _: 4;
    /// Indicates that alias detection has completed since the last system reset and there are no aliasing addresses. Resets to 0.
    pub alias_check_complete, _: 5;
    /// Indicates that SEV-TIO is enabled.
    pub tio_enabled, _ : 7

}

impl Display for PlatformInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"Platform Info ({}):
  SMT Enabled:               {}
  TSME Enabled:              {}
  ECC Enabled:               {}
  RAPL Disabled:             {}
  Ciphertext Hiding Enabled: {}
  Alias Check Complete:      {}
  SEV-TIO Enabled:           {}"#,
            self.0,
            self.smt_enabled(),
            self.tsme_enabled(),
            self.ecc_enabled(),
            self.rapl_disabled(),
            self.ciphertext_hiding_enabled(),
            self.alias_check_complete(),
            self.tio_enabled()
        )
    }
}

impl From<u64> for PlatformInfo {
    fn from(value: u64) -> Self {
        PlatformInfo(value)
    }
}

impl From<PlatformInfo> for u64 {
    fn from(value: PlatformInfo) -> Self {
        value.0
    }
}

impl Encoder<()> for PlatformInfo {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

impl Decoder<()> for PlatformInfo {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let info = reader.read_bytes()?;
        Ok(Self(info))
    }
}

impl ByteParser<()> for PlatformInfo {
    type Bytes = [u8; 8];
    const EXPECTED_LEN: Option<usize> = Some(8);
}

bitfield! {
    /// When an attestation report is requested, the user can request to have the report to not be signed, or sign with different keys. The user may also
    /// pass in the author key when launching the guest. This field provides that information and will be present in the attestation report.
    ///
    /// | Bit(s) | Name              | Description                                                                                                        >
    /// |--------|-------------------|-------------------------------------------------------------------------------------------------------------------->
    /// | 0      | AUTHOR_KEY_EN     | Indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn. >
    /// | 1      | MASK_CHIP_KEY     | The value of MaskChipKey.                                                                                          >
    /// | 4:2    | SIGNING_KEY       | Encodes the key used to sign this report.                                                                          >
    /// | 5:31   | -                 | Reserved. Must be zero.                                                                                            >
    #[repr(C)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
    pub struct KeyInfo(u32);
    impl Debug;
    /// AUTHOR_KEY_EN field: Indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST
    pub author_key_en, _: 0;
    /// MASK_CHIP_KEY field: The value of MaskChipKey
    /// (0) Firmware signs the attestation report with either the VCEK OR VLEK.
    /// (1) The firmware writes 0s into the SIGNATURE field instead of signing the report.
    pub mask_chip_key, _: 1;
    /// SIGNING_KEY field: Encodes the key used to sign this report.
    /// (0) VCEK
    /// (1) VLEK
    /// (2-6) RESERVED
    /// (7) NONE
    pub signing_key, _: 4,2;

}

impl Encoder<()> for KeyInfo {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0.to_le_bytes(), ())?;
        Ok(())
    }
}

impl Decoder<()> for KeyInfo {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let info = reader.read_bytes()?;
        Ok(Self(info))
    }
}

impl ByteParser<()> for KeyInfo {
    type Bytes = [u8; 4];
    const EXPECTED_LEN: Option<usize> = Some(4);
}

impl From<u32> for KeyInfo {
    fn from(value: u32) -> Self {
        KeyInfo(value)
    }
}

impl From<KeyInfo> for u32 {
    fn from(value: KeyInfo) -> Self {
        value.0
    }
}

impl Display for KeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let signing_key = match self.signing_key() {
            0 => "vcek",
            1 => "vlek",
            7 => "none",
            _ => "unknown",
        };

        write!(
            f,
            r#"Key Information:
    author key enabled: {}
    mask chip key:      {}
    signing key:        {}"#,
            self.author_key_en(),
            self.mask_chip_key(),
            signing_key
        )
    }
}

#[cfg(test)]
mod tests {

    use std::ops::Range;

    use super::*;
    const CHIP_ID_RANGE: Range<usize> = 0x1A0..0x1E0;

    #[test]
    fn test_derive_key_new() {
        let expected: DerivedKey = DerivedKey {
            root_key_select: 0,
            _reserved_0: 0,
            guest_field_select: GuestFieldSelect(0),
            vmpl: 0,
            guest_svn: 0,
            tcb_version: 0,
            launch_mit_vector: None,
        };

        let guest_field: GuestFieldSelect = GuestFieldSelect(0);

        let actual: DerivedKey = DerivedKey::new(false, guest_field, 0, 0, 0, None);

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_derive_key_get_root_key_select() {
        let dk_struct: DerivedKey = DerivedKey {
            root_key_select: 0,
            _reserved_0: 0,
            guest_field_select: GuestFieldSelect(0),
            vmpl: 0,
            guest_svn: 0,
            tcb_version: 0,
            launch_mit_vector: None,
        };

        let expected: u32 = 0;
        let actual: u32 = dk_struct.get_root_key_select();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_guest_field_select_all_on() {
        let actual: GuestFieldSelect = GuestFieldSelect(0b111111);

        assert!(actual.get_guest_policy());
        assert!(actual.get_image_id());
        assert!(actual.get_family_id());
        assert!(actual.get_measurement());
        assert!(actual.get_svn());
        assert!(actual.get_tcb_version());
    }

    #[test]
    fn test_guest_field_select_all_off() {
        let actual: GuestFieldSelect = GuestFieldSelect(0);

        assert!(!actual.get_guest_policy());
        assert!(!actual.get_image_id());
        assert!(!actual.get_family_id());
        assert!(!actual.get_measurement());
        assert!(!actual.get_svn());
        assert!(!actual.get_tcb_version());
    }

    #[test]
    fn test_report_body_fmt_v2_zero() {
        // Build a full firmware report (1184) with v2 and a non-masked chip_id.
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];

        // version: u32 LE at 0x00..0x04
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes());

        // sig algo
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        // Make chip_id non-zero so v2 parsing doesn't error out
        bytes[CHIP_ID_RANGE.start] = 1;

        let report = Report::from_bytes(&bytes).unwrap();
        let body = ReportBody::from_bytes(report.body).unwrap();

        let expected: &str = r#"Attestation Report:

Version:                      V2

Guest SVN:                    0

Guest Policy (0x0):
  ABI Major:     0
  ABI Minor:     0
  SMT Allowed:   false
  Migrate MA:    false
  Debug Allowed: false
  Single Socket: false
  CXL Allowed:   false
  AEX 256 XTS:   false
  RAPL Allowed:  false
  Ciphertext hiding: false
  Page Swap Disable: false

Family ID:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Image ID:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

VMPL:                         0

Signature Algorithm:          ECDSA with SECP384R1

Current TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         0

Platform Info (0):
  SMT Enabled:               false
  TSME Enabled:              false
  ECC Enabled:               false
  RAPL Disabled:             false
  Ciphertext Hiding Enabled: false
  Alias Check Complete:      false
  SEV-TIO Enabled:           false

Key Information:
    author key enabled: false
    mask chip key:      false
    signing key:        vcek

Report Data:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Measurement:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Host Data:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

ID Key Digest:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Author Key Digest:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Report ID:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Report ID Migration Agent:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Reported TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         0

CPUID Family ID:              None

CPUID Model ID:               None

CPUID Stepping:               None

Chip ID:
01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Committed TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         0

Current Version:              0.0.0

Committed Version:            0.0.0

Launch TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         0

Launch Mitigation Vector:     None

Current Mitigation Vector:    None
"#;

        assert_eq!(expected, body.to_string());
    }

    #[test]
    fn test_report_copy() {
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];
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
    fn test_guest_policy_zeroed() {
        let gp: GuestPolicy = GuestPolicy(0);

        assert_eq!(gp.abi_minor(), 0);
        assert_eq!(gp.abi_major(), 0);
        assert!(!gp.smt_allowed());
        assert!(!gp.migrate_ma_allowed());
        assert!(!gp.debug_allowed());
        assert!(!gp.single_socket_required());
        assert!(!gp.cxl_allowed());
        assert!(!gp.mem_aes_256_xts());
        assert!(!gp.rapl_dis());
        assert!(!gp.ciphertext_hiding());
    }

    #[test]
    fn test_guest_policy_max() {
        let gp: GuestPolicy = GuestPolicy(0b1111111111111111111111111);

        assert_eq!(gp.abi_minor(), 0b11111111);
        assert_eq!(gp.abi_major(), 0b11111111);
        assert!(gp.smt_allowed());
        assert!(gp.migrate_ma_allowed());
        assert!(gp.debug_allowed());
        assert!(gp.single_socket_required());
        assert!(gp.cxl_allowed());
        assert!(gp.mem_aes_256_xts());
        assert!(gp.rapl_dis());
        assert!(gp.ciphertext_hiding());
    }

    #[test]
    fn test_set_guest_policy_max() {
        let mut gp: GuestPolicy = Default::default();

        assert_eq!(gp.abi_minor(), 0);
        gp.set_abi_minor(1);
        assert_eq!(gp.abi_minor(), 0b1);

        assert_eq!(gp.abi_major(), 0);
        gp.set_abi_major(1);
        assert_eq!(gp.abi_major(), 0b1);

        assert!(!gp.smt_allowed());
        gp.set_smt_allowed(true);
        assert!(gp.smt_allowed());

        assert!(!gp.migrate_ma_allowed());
        gp.set_migrate_ma_allowed(true);
        assert!(gp.migrate_ma_allowed());

        assert!(!gp.debug_allowed());
        gp.set_debug_allowed(true);
        assert!(gp.debug_allowed());

        assert!(!gp.single_socket_required());
        gp.set_single_socket_required(true);
        assert!(gp.single_socket_required());

        assert!(!gp.cxl_allowed());
        gp.set_cxl_allowed(true);
        assert!(gp.cxl_allowed());

        assert!(!gp.mem_aes_256_xts());
        gp.set_mem_aes_256_xts(true);
        assert!(gp.mem_aes_256_xts());

        assert!(!gp.rapl_dis());
        gp.set_rapl_dis(true);
        assert!(gp.rapl_dis());

        assert!(!gp.ciphertext_hiding());
        gp.set_ciphertext_hiding(true);
        assert!(gp.ciphertext_hiding());
    }

    #[test]
    fn test_guest_policy_from_u64() {
        let gp: GuestPolicy = GuestPolicy(5);

        // Bit 17 of the guest policy is reserved and must always be set to 1.
        let expected: u64 = (1 << 17) | 5;

        assert_eq!(u64::from(gp), expected);
    }

    #[test]
    fn test_platform_info_zeroed() {
        let expected: PlatformInfo = PlatformInfo(0);

        assert!(!expected.smt_enabled());
        assert!(!expected.tsme_enabled());
        assert!(!expected.ecc_enabled());
        assert!(!expected.rapl_disabled());
        assert!(!expected.ciphertext_hiding_enabled());
        assert!(!expected.alias_check_complete());
    }

    #[test]
    fn test_platform_info_full() {
        let expected: PlatformInfo = PlatformInfo(0b111111);

        assert!(expected.smt_enabled());
        assert!(expected.tsme_enabled());
        assert!(expected.ecc_enabled());
        assert!(expected.rapl_disabled());
        assert!(expected.ciphertext_hiding_enabled());
        assert!(expected.alias_check_complete());
    }

    #[test]
    fn test_platform_info_fmt() {
        let expected: &str = r#"Platform Info (0):
  SMT Enabled:               false
  TSME Enabled:              false
  ECC Enabled:               false
  RAPL Disabled:             false
  Ciphertext Hiding Enabled: false
  Alias Check Complete:      false
  SEV-TIO Enabled:           false"#;
        let actual: PlatformInfo = PlatformInfo(0);

        assert_eq!(expected, actual.to_string());
    }

    #[test]
    fn test_key_info_zeroed() {
        let expected: KeyInfo = KeyInfo(0);

        assert!(!expected.author_key_en());
        assert!(!expected.mask_chip_key());

        assert_eq!(expected.signing_key(), 0);
    }

    #[test]
    fn test_key_info_max() {
        let expected: KeyInfo = KeyInfo(0b11111);

        assert!(expected.author_key_en());
        assert!(expected.mask_chip_key());
        assert_eq!(expected.signing_key(), 0b111);
    }

    #[test]
    fn test_key_info_fmt_vcek() {
        let expected: &str = r#"Key Information:
    author key enabled: false
    mask chip key:      false
    signing key:        vcek"#;
        let actual: KeyInfo = KeyInfo(0);

        assert_eq!(expected, actual.to_string());
    }

    #[test]
    fn test_key_info_fmt_vlek() {
        let expected: &str = r#"Key Information:
    author key enabled: false
    mask chip key:      false
    signing key:        vlek"#;
        let actual: KeyInfo = KeyInfo(0b100);

        assert_eq!(expected, actual.to_string());
    }

    #[test]
    fn test_key_info_fmt_none() {
        let expected: &str = r#"Key Information:
    author key enabled: false
    mask chip key:      false
    signing key:        none"#;
        let actual: KeyInfo = KeyInfo(0b11100);

        assert_eq!(expected, actual.to_string());
    }

    #[test]
    fn test_key_info_fmt_unknown() {
        let expected: &str = r#"Key Information:
    author key enabled: false
    mask chip key:      false
    signing key:        unknown"#;
        let actual: KeyInfo = KeyInfo(0b11000);

        assert_eq!(expected, actual.to_string());
    }

    #[test]
    fn test_platform_info_v2_serialization() {
        let original = PlatformInfo(0b11111);
        // Test encoding and decoding
        let buffer = original.to_bytes().unwrap();
        let decoded = PlatformInfo::from_bytes(&buffer).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_key_info_serialization() {
        let original = KeyInfo(0b11111);

        // Test encoding and decoding
        let buffer = original.to_bytes().unwrap();
        let decoded = KeyInfo::from_bytes(&buffer).unwrap();

        assert_eq!(original, decoded);
        assert!(decoded.author_key_en());
        assert!(decoded.mask_chip_key());
        assert_eq!(decoded.signing_key(), 0b111);
    }

    #[test]
    fn test_guest_policy_serialization() {
        let mut original: GuestPolicy = Default::default();
        original.set_abi_major(2);
        original.set_abi_minor(1);
        original.set_smt_allowed(true);
        original.set_debug_allowed(true);

        let buffer = original.to_bytes().unwrap();
        let decoded = GuestPolicy::from_bytes(&buffer).unwrap();
        assert_eq!(original, decoded);
    }

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
    fn test_boundary_value_serialization() {
        // Test max values
        let platform_info = PlatformInfo(u64::MAX);
        let key_info = KeyInfo(u32::MAX);
        let guest_policy = GuestPolicy(u64::MAX);

        // Verify serialization/deserialization preserves max values
        assert_eq!(
            platform_info,
            PlatformInfo::from_bytes(&platform_info.to_bytes().unwrap()).unwrap()
        );
        assert_eq!(
            key_info,
            KeyInfo::from_bytes(&key_info.to_bytes().unwrap()).unwrap()
        );
        assert_eq!(
            guest_policy,
            GuestPolicy::from_bytes(&guest_policy.to_bytes().unwrap()).unwrap()
        );
    }

    #[test]
    fn test_guest_field_select_operations() {
        let mut field = GuestFieldSelect::default();

        field.set_guest_policy(true);
        assert!(field.get_guest_policy());

        field.set_image_id(true);
        assert!(field.get_image_id());

        field.set_family_id(true);
        assert!(field.get_family_id());

        field.set_measurement(true);
        assert!(field.get_measurement());
    }

    #[test]
    fn test_derived_key_fields() {
        let key = DerivedKey::new(true, GuestFieldSelect(0xFF), 2, 3, 0x1234, None);
        assert_eq!(key.get_root_key_select(), 1);
        assert_eq!(key.vmpl, 2);
        assert_eq!(key.guest_svn, 3);
        assert_eq!(key.tcb_version, 0x1234);
    }

    #[test]
    fn test_key_info_all_combinations() {
        let mut info = KeyInfo(0);

        // Test VCEK
        assert_eq!(info.signing_key(), 0);
        assert!(!info.author_key_en());

        // Test VLEK
        info = KeyInfo(0b100);
        assert_eq!(info.signing_key(), 1);

        // Test None
        info = KeyInfo(0b11100);
        assert_eq!(info.signing_key(), 7);
    }

    #[test]
    fn test_report_body_selected_fields() {
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];

        // v2: version u32 LE at 0x00..0x04
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes());

        // v2 requires chip_id not fully masked (not all zeros)
        bytes[CHIP_ID_RANGE.start] = 1;

        // guest_svn at 0x04..0x08
        bytes[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());

        // vmpl at 0x30..0x34
        bytes[0x30..0x34].copy_from_slice(&3u32.to_le_bytes());

        // signature alorithm
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();

        // NOTE: parsing-only test: do NOT use TryFrom/verify path here
        let body = ReportBody::from_bytes(report.body).unwrap();

        assert_eq!(body.version, ReportVariant::V2);
        assert_eq!(body.guest_svn, 1);
        assert_eq!(body.vmpl, 3);
        assert_eq!(body.measurement, &[0u8; 48]);
        assert_eq!(body.sig_algo, SignatureAlgorithm::EcdsaSecp384r1)
    }

    #[test]
    fn test_guest_policy_combined_fields() {
        let mut policy: GuestPolicy = Default::default();

        policy.set_abi_major(2);
        policy.set_abi_minor(1);
        policy.set_smt_allowed(true);
        policy.set_debug_allowed(true);

        assert_eq!(policy.abi_major(), 2);
        assert_eq!(policy.abi_minor(), 1);
        assert!(policy.smt_allowed());
        assert!(policy.debug_allowed());

        let policy_u64: u64 = policy.into();
        assert_eq!(policy_u64 & (1 << 17), 1 << 17); // Reserved bit 17 must be 1
    }

    #[test]
    fn test_version_display() {
        let version = Version::new(3, 2, 1);
        assert_eq!(version.to_string(), "3.2.1");

        let max_version = Version::new(255, 255, 255);
        assert_eq!(max_version.to_string(), "255.255.255");

        let min_version = Version::new(0, 0, 0);
        assert_eq!(min_version.to_string(), "0.0.0");
    }

    #[test]
    fn test_version_byte_parser() {
        // Test from_bytes
        let bytes = [1, 2, 3];
        let version = Version::from_bytes(&bytes).unwrap();
        assert_eq!(version, Version::new(3, 2, 1));

        // Test to_bytes
        let version = Version::new(4, 5, 6);
        let bytes = version.to_bytes().unwrap();
        assert_eq!(bytes, [6, 5, 4]);

        // Test roundtrip
        let original = Version::new(7, 8, 9);
        let bytes = original.to_bytes().unwrap();
        let roundtrip = Version::from_bytes(&bytes).unwrap();
        assert_eq!(original, roundtrip);

        // Test default
        assert_eq!(<Version as Default>::default(), Version::new(0, 0, 0));
    }

    #[test]
    fn test_report_from_bytes_ok() {
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2
        bytes[CHIP_ID_RANGE.start] = 1; // unmask chip id

        // signature alorithm
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let report = Report::from_bytes(bytes.as_slice());
        assert!(report.is_ok());

        // Also ensure the body can be parsed
        let report = report.unwrap();
        assert!(ReportBody::from_bytes(report.body).is_ok());
    }

    #[test]
    fn test_report_from_bytes_rejects_bad_len() {
        let bytes = vec![0u8; ATT_REP_FW_LEN - 1];
        let err = Report::from_bytes(&bytes).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_report_body_parse_roundtrip_like() {
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2
        bytes[CHIP_ID_RANGE.start] = 1; // unmask

        // family_id and image_id
        bytes[0x10..0x20].copy_from_slice(&[0xAA; 16]);
        bytes[0x20..0x30].copy_from_slice(&[0xBB; 16]);

        // guest_svn
        bytes[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());

        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();
        let body = ReportBody::from_bytes(report.body).unwrap();

        assert_eq!(body.family_id, &[0xAA; 16]);
        assert_eq!(body.image_id, &[0xBB; 16]);
        assert_eq!(body.guest_svn, 1);
    }

    #[test]
    fn test_version_edge_cases() {
        // Test max values
        let version = Version::new(255, 255, 255);
        let bytes = version.to_bytes().unwrap();
        assert_eq!(bytes, [255, 255, 255]);

        // Test mixed values
        let version = Version::new(0, 255, 0);
        let bytes = version.to_bytes().unwrap();
        assert_eq!(bytes, [0, 255, 0]);
    }

    #[test]
    fn test_version_ordering() {
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 0, 1);
        let v3 = Version::new(1, 1, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);

        // Test equality
        assert_eq!(Version::new(1, 2, 3), Version::new(1, 2, 3));
        assert_ne!(Version::new(1, 2, 3), Version::new(1, 2, 4));
    }

    #[test]
    fn test_version_copy() {
        let original = Version::new(1, 2, 3);
        let cloned = original;

        assert_eq!(original, cloned);
        assert_eq!(original.to_bytes().unwrap(), cloned.to_bytes().unwrap());
    }

    #[test]
    fn test_platform_v2_info_from_u64() {
        let value: u64 = 0xFFFF;
        let platform_info = PlatformInfo::from(value);
        assert_eq!(platform_info.0, value);

        let value: u64 = 0;
        let platform_info = PlatformInfo::from(value);
        assert_eq!(platform_info.0, value);

        let value: u64 = u64::MAX;
        let platform_info = PlatformInfo::from(value);
        assert_eq!(platform_info.0, value);
    }

    #[test]
    fn test_platform_v2_info_into_u64() {
        let platform_info = PlatformInfo(0xFFFF);
        let value: u64 = platform_info.into();
        assert_eq!(value, 0xFFFF);

        let platform_info = PlatformInfo(0);
        let value: u64 = platform_info.into();
        assert_eq!(value, 0);

        let platform_info = PlatformInfo(u64::MAX);
        let value: u64 = platform_info.into();
        assert_eq!(value, u64::MAX);
    }

    #[test]
    fn test_key_info_from_u32() {
        let value: u32 = 0xFFFF;
        let key_info = KeyInfo::from(value);
        assert_eq!(key_info.0, value);

        let value: u32 = 0;
        let key_info = KeyInfo::from(value);
        assert_eq!(key_info.0, value);

        let value: u32 = u32::MAX;
        let key_info = KeyInfo::from(value);
        assert_eq!(key_info.0, value);
    }

    #[test]
    fn test_key_info_into_u32() {
        let key_info = KeyInfo(0xFFFF);
        let value: u32 = key_info.into();
        assert_eq!(value, 0xFFFF);

        let key_info = KeyInfo(0);
        let value: u32 = key_info.into();
        assert_eq!(value, 0);

        let key_info = KeyInfo(u32::MAX);
        let value: u32 = key_info.into();
        assert_eq!(value, u32::MAX);
    }

    #[test]
    fn test_chip_id_v2_genoa_like_allowed() {
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2

        // Genoa-like: full 64 bytes used (i.e., not "first 8 nonzero then rest zero")
        let vcek_bytes = [
            0xD4, 0x95, 0x54, 0xEC, 0x71, 0x7F, 0x4E, 0x5B, 0x0F, 0xE6, 0xB1, 0x43, 0xBC, 0xF0,
            0x40, 0x5B, 0xD7, 0xAE, 0x30, 0x47, 0x27, 0xED, 0xF4, 0x66, 0x03, 0xF2, 0xA7, 0x6A,
            0xEF, 0x6A, 0x3A, 0xBC, 0x15, 0xD7, 0xAF, 0x38, 0xDB, 0x75, 0x70, 0x39, 0x02, 0x9F,
            0x0E, 0xFA, 0xCF, 0xD0, 0x8E, 0x24, 0x43, 0x24, 0x88, 0x47, 0x38, 0xC7, 0x2B, 0x08,
            0x2E, 0x2F, 0x87, 0xA4, 0x4D, 0x54, 0x1E, 0xB6,
        ];

        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        bytes[CHIP_ID_RANGE.clone()].copy_from_slice(&vcek_bytes);

        let report = Report::from_bytes(&bytes).unwrap();
        let body = ReportBody::from_bytes(report.body).unwrap();

        // Should have cpuid fields absent in v2
        assert_eq!(body.cpuid_fam_id, None);
        assert_eq!(body.cpuid_mod_id, None);
        assert_eq!(body.cpuid_step, None);

        // Should preserve chip_id bytes
        assert_eq!(body.chip_id, &vcek_bytes);
    }

    #[test]
    fn test_chip_id_v2_turin_like_allowed() {
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2

        let mut chip = [0u8; 64];
        chip[0..8].copy_from_slice(&[0xD4, 0x95, 0x54, 0xEC, 0x71, 0x7F, 0x4E, 0x5B]);
        // rest remains zero
        bytes[CHIP_ID_RANGE.clone()].copy_from_slice(&chip);

        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();
        let body = ReportBody::from_bytes(report.body).unwrap();

        assert_eq!(body.chip_id, &chip);
    }

    #[test]
    fn test_chip_id_v2_masked_rejected() {
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2
                                                                // chip_id left as all zeros

        // Setting sig algo
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();
        let err = ReportBody::from_bytes(report.body).unwrap_err();
        assert!(err.to_string().contains("Chip ID is masked"));
    }

    #[test]
    fn test_report_from_bytes_splits_body_and_signature() {
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];
        // signature alorithm
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        let r = Report::from_bytes(&bytes).unwrap();

        assert_eq!(r.body.len(), 0x2a0);
        assert_eq!(r.signature.len(), 0x49f + 1 - 0x2a0);
        assert_eq!(r.body.as_ptr(), bytes.as_ptr());
        assert_eq!(
            unsafe { r.signature.as_ptr().offset_from(bytes.as_ptr()) } as usize,
            0x2a0
        );
    }

    #[test]
    fn test_report_variant_tryfrom() {
        assert_eq!(ReportVariant::try_from(2).unwrap(), ReportVariant::V2);
        assert_eq!(ReportVariant::try_from(3).unwrap(), ReportVariant::V3);
        assert_eq!(ReportVariant::try_from(4).unwrap(), ReportVariant::V3);
        assert_eq!(ReportVariant::try_from(5).unwrap(), ReportVariant::V5);
        assert!(ReportVariant::try_from(99).is_err());
    }

    #[test]
    fn test_report_body_rejects_nonzero_reserved_0x4c() {
        let mut bytes = vec![0u8; ATT_REP_FW_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes());
        bytes[CHIP_ID_RANGE.start] = 1;

        // Setting sig algo
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        bytes[0x4C] = 1; // reserved byte non-zero

        let r = Report::from_bytes(&bytes).unwrap();
        assert!(ReportBody::from_bytes(r.body).is_err());
    }
}
