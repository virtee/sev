// SPDX-License-Identifier: Apache-2.0

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use crate::certs::snp::{Certificate, Chain, Verifiable};

use crate::{
    certs::snp::ecdsa::Signature,
    error::AttestationReportError,
    firmware::host::TcbVersion,
    util::{
        array::Array,
        parser::{ByteParser, ReadExt, WriteExt},
    },
};

use serde::{Deserialize, Serialize};

use std::{fmt::Display, io::Write};

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use std::{
    convert::TryFrom,
    io::{self, ErrorKind},
};

#[cfg(feature = "openssl")]
use std::io::Error;

use bitfield::bitfield;

#[cfg(feature = "openssl")]
use openssl::{ecdsa::EcdsaSig, sha::Sha384};

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
}

impl DerivedKey {
    /// Create a new instance for requesting an DerivedKey.
    pub fn new(
        root_key_select: bool,
        guest_field_select: GuestFieldSelect,
        vmpl: u32,
        guest_svn: u32,
        tcb_version: u64,
    ) -> Self {
        Self {
            root_key_select: u32::from(root_key_select),
            _reserved_0: Default::default(),
            guest_field_select,
            vmpl,
            guest_svn,
            tcb_version,
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
    /// |63:6|\-|Reserved. Must be zero.|
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
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
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

impl Default for Version {
    fn default() -> Self {
        ByteParser::default()
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

impl ByteParser for Version {
    type Bytes = [u8; 3];

    #[inline(always)]
    fn from_bytes(bytes: Self::Bytes) -> Self {
        let [build, minor, major] = bytes;
        Self {
            major,
            minor,
            build,
        }
    }

    #[inline(always)]
    fn to_bytes(&self) -> Self::Bytes {
        [self.build, self.minor, self.major]
    }

    #[inline(always)]
    fn default() -> Self {
        Self {
            major: 0,
            minor: 0,
            build: 0,
        }
    }
}

/// Possible variants of the attestation report.
pub enum ReportVariant {
    /// Version 2 of the Attestation Report.
    V2,

    /// Version 3 of the Attestation Report for PreTurin CPUs.
    V3PreTurin,

    /// Version 3 of the Attestation Report for Turin+ CPUs.
    V3Turin,
}

impl ReportVariant {
    /// Determine the variant of the Attestation Report based upon the bytes provided.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let mut version_bytes: [u8; 4] = [0; 4];
        version_bytes.copy_from_slice(&bytes[0..4]);
        let version: u32 = u32::from_le_bytes(version_bytes);

        Ok(match version {
            0 | 1 => return Err(std::io::ErrorKind::Unsupported.into()),
            2 => Self::V2,
            _ => {
                let family: u8 = bytes[392];
                if family >= 0x1A {
                    Self::V3Turin
                } else {
                    Self::V3PreTurin
                }
            }
        })
    }
}

/// Version 3 of the attestation report
/// Systems that contain firmware starting from the spec release 1.56 will use this attestation report.
/// This version adds:
/// The CPUID Family, Model and Stepping fields
/// The Alias_Check_Complete field in the PlatformInfo field
#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttestationReport {
    /// Version number of this attestation report. Set to 2h for this specification.
    pub version: u32,
    /// The guest SVN.
    pub guest_svn: u32,
    /// The guest policy.
    pub policy: GuestPolicy,
    /// The family ID provided at launch.
    pub family_id: Array<u8, 16>,
    /// The image ID provided at launch.
    pub image_id: Array<u8, 16>,
    /// The request VMPL for the attestation report.
    pub vmpl: u32,
    /// The signature algorithm used to sign this report.
    pub sig_algo: u32,
    /// Current TCB. See SNPTcbVersion
    pub current_tcb: TcbVersion,
    /// Information about the platform. See PlatformInfo
    pub plat_info: PlatformInfo,
    /// Information related to signing keys in the report. See KeyInfo
    pub key_info: KeyInfo,

    /// Guest-provided 512 Bits of Data
    pub report_data: Array<u8, 64>,

    /// The measurement calculated at launch.
    pub measurement: Array<u8, 48>,
    /// Data provided by the hypervisor at launch.
    pub host_data: Array<u8, 32>,

    /// SHA-384 digest of the ID public key that signed the ID block provided
    /// in SNP_LANUNCH_FINISH.
    pub id_key_digest: Array<u8, 48>,

    /// SHA-384 digest of the Author public key that certified the ID key,
    /// if provided in SNP_LAUNCH_FINSIH. Zeroes if AUTHOR_KEY_EN is 1.
    pub author_key_digest: Array<u8, 48>,
    /// Report ID of this guest.
    pub report_id: Array<u8, 32>,
    /// Report ID of this guest's migration agent (if applicable).
    pub report_id_ma: Array<u8, 32>,
    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: TcbVersion,
    /// CPUID Familiy ID (Combined Extended Family ID and Family ID)
    pub cpuid_fam_id: Option<u8>,
    /// CPUID Model (Combined Extended Model and Model fields)
    pub cpuid_mod_id: Option<u8>,
    /// CPUID Stepping
    pub cpuid_step: Option<u8>,

    /// If MaskChipId is set to 0, Identifier unique to the chip.
    /// Otherwise set to 0h.
    pub chip_id: Array<u8, 64>,
    /// CommittedTCB
    pub committed_tcb: TcbVersion,
    /// The build number of CurrentVersion
    pub current: Version,
    /// The build number of CommittedVersion
    pub committed: Version,
    /// The CurrentTcb at the time the guest was launched or imported.
    pub launch_tcb: TcbVersion,
    /// Signature of bytes 0 to 0x29F inclusive of this report.
    /// The format of the signature is found within Signature.
    pub signature: Signature,
}

impl AttestationReport {
    #[inline(always)]
    /// Checkes if the MaskChipId is set to 1. If not, then it will check if
    /// the CHIP_ID is Turin-like.
    fn chip_id_is_turin_like(bytes: &[u8]) -> Result<bool, AttestationReportError> {
        // Chip ID -> 0x1A0-0x1E0
        if bytes == [0; 64] {
            return Err(AttestationReportError::MaskedChipId);
        }

        // Last 8 bytes of CHIP_ID are zero, then it is Turin Like.
        Ok(bytes[8..] == [0; 56])
    }

    /// Attempts to parse an AttestationReport structure from raw bytes.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, std::io::Error> {
        let variant = ReportVariant::from_bytes(bytes)?;

        let stepper: &mut &[u8] = &mut bytes;

        if stepper.len() != 1184 {
            return Err(std::io::ErrorKind::InvalidData)?;
        }

        Ok(match variant {
            ReportVariant::V2 => {
                // Pass only the bytes from the attestation report byte
                // stream which contains the 32-bit field containing the
                // MASK_CHIP_ID values.
                //
                // Skip the first 8 bytes of the `CHIP_ID` field and see if
                // the remaining bytes are all zero (how Turin+ behaves because
                // of SPN fields for hash-stick algorithm).
                if Self::chip_id_is_turin_like(&stepper[0x1A0..0x1E0])? {
                    AttestationReport {
                        version: stepper.parse_bytes::<_, 0>()?,
                        guest_svn: stepper.parse_bytes::<_, 0>()?,
                        policy: stepper.parse_bytes::<_, 0>()?,
                        family_id: stepper.parse_bytes::<_, 0>()?,
                        image_id: stepper.parse_bytes::<_, 0>()?,
                        vmpl: stepper.parse_bytes::<_, 0>()?,
                        sig_algo: stepper.parse_bytes::<_, 0>()?,
                        current_tcb: TcbVersion::from_turin_bytes(
                            &stepper.parse_bytes::<[u8; 8], 0>()?,
                        ),
                        plat_info: stepper.parse_bytes::<_, 0>()?,
                        key_info: stepper.parse_bytes::<_, 0>()?,
                        report_data: stepper.parse_bytes::<_, 4>()?,
                        measurement: stepper.parse_bytes::<_, 0>()?,
                        host_data: stepper.parse_bytes::<_, 0>()?,
                        id_key_digest: stepper.parse_bytes::<_, 0>()?,
                        author_key_digest: stepper.parse_bytes::<_, 0>()?,
                        report_id: stepper.parse_bytes::<_, 0>()?,
                        report_id_ma: stepper.parse_bytes::<_, 0>()?,
                        reported_tcb: TcbVersion::from_turin_bytes(
                            &stepper.parse_bytes::<[u8; 8], 0>()?,
                        ),
                        cpuid_fam_id: None,
                        cpuid_mod_id: None,
                        cpuid_step: None,
                        chip_id: stepper.parse_bytes::<_, 24>()?,
                        committed_tcb: TcbVersion::from_turin_bytes(
                            &stepper.parse_bytes::<[u8; 8], 0>()?,
                        ),
                        current: stepper.parse_bytes::<_, 0>()?,
                        committed: stepper.parse_bytes::<_, 1>()?,
                        launch_tcb: TcbVersion::from_turin_bytes(
                            &stepper.parse_bytes::<[u8; 8], 1>()?,
                        ),
                        signature: stepper.parse_bytes::<_, 168>()?,
                    }
                } else {
                    AttestationReport {
                        version: stepper.parse_bytes::<_, 0>()?,
                        guest_svn: stepper.parse_bytes::<_, 0>()?,
                        policy: stepper.parse_bytes::<_, 0>()?,
                        family_id: stepper.parse_bytes::<_, 0>()?,
                        image_id: stepper.parse_bytes::<_, 0>()?,
                        vmpl: stepper.parse_bytes::<_, 0>()?,
                        sig_algo: stepper.parse_bytes::<_, 0>()?,
                        current_tcb: TcbVersion::from_legacy_bytes(
                            &stepper.parse_bytes::<[u8; 8], 0>()?,
                        ),
                        plat_info: stepper.parse_bytes::<_, 0>()?,
                        key_info: stepper.parse_bytes::<_, 0>()?,
                        report_data: stepper.parse_bytes::<_, 4>()?,
                        measurement: stepper.parse_bytes::<_, 0>()?,
                        host_data: stepper.parse_bytes::<_, 0>()?,
                        id_key_digest: stepper.parse_bytes::<_, 0>()?,
                        author_key_digest: stepper.parse_bytes::<_, 0>()?,
                        report_id: stepper.parse_bytes::<_, 0>()?,
                        report_id_ma: stepper.parse_bytes::<_, 0>()?,
                        reported_tcb: TcbVersion::from_legacy_bytes(
                            &stepper.parse_bytes::<[u8; 8], 0>()?,
                        ),
                        cpuid_fam_id: None,
                        cpuid_mod_id: None,
                        cpuid_step: None,
                        chip_id: stepper.parse_bytes::<_, 24>()?,
                        committed_tcb: TcbVersion::from_legacy_bytes(
                            &stepper.parse_bytes::<[u8; 8], 0>()?,
                        ),
                        current: stepper.parse_bytes::<_, 0>()?,
                        committed: stepper.parse_bytes::<_, 1>()?,
                        launch_tcb: TcbVersion::from_legacy_bytes(
                            &stepper.parse_bytes::<[u8; 8], 1>()?,
                        ),
                        signature: stepper.parse_bytes::<_, 168>()?,
                    }
                }
            }
            ReportVariant::V3PreTurin => AttestationReport {
                version: stepper.parse_bytes::<_, 0>()?,
                guest_svn: stepper.parse_bytes::<_, 0>()?,
                policy: stepper.parse_bytes::<_, 0>()?,
                family_id: stepper.parse_bytes::<_, 0>()?,
                image_id: stepper.parse_bytes::<_, 0>()?,
                vmpl: stepper.parse_bytes::<_, 0>()?,
                sig_algo: stepper.parse_bytes::<_, 0>()?,
                current_tcb: TcbVersion::from_legacy_bytes(&stepper.parse_bytes::<[u8; 8], 0>()?),
                plat_info: stepper.parse_bytes::<_, 0>()?,
                key_info: stepper.parse_bytes::<_, 0>()?,
                report_data: stepper.parse_bytes::<_, 4>()?,
                measurement: stepper.parse_bytes::<_, 0>()?,
                host_data: stepper.parse_bytes::<_, 0>()?,
                id_key_digest: stepper.parse_bytes::<_, 0>()?,
                author_key_digest: stepper.parse_bytes::<_, 0>()?,
                report_id: stepper.parse_bytes::<_, 0>()?,
                report_id_ma: stepper.parse_bytes::<_, 0>()?,
                reported_tcb: TcbVersion::from_legacy_bytes(&stepper.parse_bytes::<[u8; 8], 0>()?),
                cpuid_fam_id: Some(stepper.parse_bytes::<_, 0>()?),
                cpuid_mod_id: Some(stepper.parse_bytes::<_, 0>()?),
                cpuid_step: Some(stepper.parse_bytes::<_, 0>()?),
                chip_id: stepper.parse_bytes::<_, 21>()?,
                committed_tcb: TcbVersion::from_legacy_bytes(&stepper.parse_bytes::<[u8; 8], 0>()?),
                current: stepper.parse_bytes::<_, 0>()?,
                committed: stepper.parse_bytes::<_, 1>()?,
                launch_tcb: TcbVersion::from_legacy_bytes(&stepper.parse_bytes::<[u8; 8], 1>()?),
                signature: stepper.parse_bytes::<_, 168>()?,
            },
            ReportVariant::V3Turin => AttestationReport {
                version: stepper.parse_bytes::<_, 0>()?,
                guest_svn: stepper.parse_bytes::<_, 0>()?,
                policy: stepper.parse_bytes::<_, 0>()?,
                family_id: stepper.parse_bytes::<_, 0>()?,
                image_id: stepper.parse_bytes::<_, 0>()?,
                vmpl: stepper.parse_bytes::<_, 0>()?,
                sig_algo: stepper.parse_bytes::<_, 0>()?,
                current_tcb: TcbVersion::from_turin_bytes(&stepper.parse_bytes::<[u8; 8], 0>()?),
                plat_info: stepper.parse_bytes::<_, 0>()?,
                key_info: stepper.parse_bytes::<_, 0>()?,
                report_data: stepper.parse_bytes::<_, 4>()?,
                measurement: stepper.parse_bytes::<_, 0>()?,
                host_data: stepper.parse_bytes::<_, 0>()?,
                id_key_digest: stepper.parse_bytes::<_, 0>()?,
                author_key_digest: stepper.parse_bytes::<_, 0>()?,
                report_id: stepper.parse_bytes::<_, 0>()?,
                report_id_ma: stepper.parse_bytes::<_, 0>()?,
                reported_tcb: TcbVersion::from_turin_bytes(&stepper.parse_bytes::<[u8; 8], 0>()?),
                cpuid_fam_id: Some(stepper.parse_bytes::<_, 0>()?),
                cpuid_mod_id: Some(stepper.parse_bytes::<_, 0>()?),
                cpuid_step: Some(stepper.parse_bytes::<_, 0>()?),
                chip_id: stepper.parse_bytes::<_, 21>()?,
                committed_tcb: TcbVersion::from_turin_bytes(&stepper.parse_bytes::<[u8; 8], 0>()?),
                current: stepper.parse_bytes::<_, 0>()?,
                committed: stepper.parse_bytes::<_, 1>()?,
                launch_tcb: TcbVersion::from_turin_bytes(&stepper.parse_bytes::<[u8; 8], 1>()?),
                signature: stepper.parse_bytes::<_, 168>()?,
            },
        })
    }

    /// Writes the Attestation Report back into the ASP binary format.
    pub fn write_bytes(self, mut handle: impl Write) -> Result<(), std::io::Error> {
        // Determine the variant based on version and CPUID step
        let variant = if self.version == 2 {
            ReportVariant::V2
        } else if self.version == 3 && (self.cpuid_fam_id.unwrap_or(0) < 0x1A) {
            ReportVariant::V3PreTurin
        } else {
            ReportVariant::V3Turin
        };

        // Write version (common to all variants)
        handle.write_bytes::<_, 0>(self.version)?;
        handle.write_bytes::<_, 0>(self.guest_svn)?;
        handle.write_bytes::<_, 0>(self.policy)?;
        handle.write_bytes::<_, 0>(self.family_id)?;
        handle.write_bytes::<_, 0>(self.image_id)?;
        handle.write_bytes::<_, 0>(self.vmpl)?;
        handle.write_bytes::<_, 0>(self.sig_algo)?;

        // Write TCB based on variant
        match variant {
            ReportVariant::V3Turin => {
                handle.write_bytes::<_, 0>(self.current_tcb.to_turin_bytes())?;
            }
            _ => {
                handle.write_bytes::<_, 0>(self.current_tcb.to_legacy_bytes())?;
            }
        }

        handle.write_bytes::<_, 0>(self.plat_info)?;
        handle.write_bytes::<_, 0>(self.key_info)?;
        handle.write_bytes::<_, 4>(self.report_data)?;
        handle.write_bytes::<_, 0>(self.measurement)?;
        handle.write_bytes::<_, 0>(self.host_data)?;
        handle.write_bytes::<_, 0>(self.id_key_digest)?;
        handle.write_bytes::<_, 0>(self.author_key_digest)?;
        handle.write_bytes::<_, 0>(self.report_id)?;
        handle.write_bytes::<_, 0>(self.report_id_ma)?;

        // Write reported TCB based on variant
        match variant {
            ReportVariant::V3Turin => {
                handle.write_bytes::<_, 0>(self.reported_tcb.to_turin_bytes())?;
            }
            _ => {
                handle.write_bytes::<_, 0>(self.reported_tcb.to_legacy_bytes())?;
            }
        }

        // Write CPUID fields based on variant
        match variant {
            ReportVariant::V2 => {
                // V2 doesn't have CPUID fields
            }
            _ => {
                // Write CPUID fields for V3 and V4
                handle.write_bytes::<_, 0>(self.cpuid_fam_id.unwrap_or(0))?;
                handle.write_bytes::<_, 0>(self.cpuid_mod_id.unwrap_or(0))?;
                handle.write_bytes::<_, 0>(self.cpuid_step.unwrap_or(0))?;
            }
        }

        // Write chip_id with appropriate padding
        match variant {
            ReportVariant::V2 => {
                handle.write_bytes::<_, 24>(self.chip_id)?;
            }
            _ => {
                handle.write_bytes::<_, 21>(self.chip_id)?;
            }
        }

        // Write committed TCB based on variant
        match variant {
            ReportVariant::V3Turin => {
                handle.write_bytes::<_, 0>(self.committed_tcb.to_turin_bytes())?;
            }
            _ => {
                handle.write_bytes::<_, 0>(self.committed_tcb.to_legacy_bytes())?;
            }
        }

        handle.write_bytes::<_, 0>(self.current)?;
        handle.write_bytes::<_, 1>(self.committed)?;

        // Write launch TCB based on variant
        match variant {
            ReportVariant::V3Turin => {
                handle.write_bytes::<_, 1>(self.launch_tcb.to_turin_bytes())?;
            }
            _ => {
                handle.write_bytes::<_, 1>(self.launch_tcb.to_legacy_bytes())?;
            }
        }

        // Write signature (common to all variants)
        handle.write_bytes::<_, 168>(self.signature)?;

        Ok(())
    }
}

impl Display for AttestationReport {
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

{}"#,
            self.version,
            self.guest_svn,
            self.policy,
            self.family_id,
            self.image_id,
            self.vmpl,
            self.sig_algo,
            self.current_tcb,
            self.plat_info,
            self.key_info,
            self.report_data,
            self.measurement,
            self.host_data,
            self.id_key_digest,
            self.author_key_digest,
            self.report_id,
            self.report_id_ma,
            self.reported_tcb,
            self.cpuid_fam_id
                .map_or("None".to_string(), |fam| fam.to_string()),
            self.cpuid_mod_id
                .map_or("None".to_string(), |model| model.to_string()),
            self.cpuid_step
                .map_or("None".to_string(), |step| step.to_string()),
            self.chip_id,
            self.committed_tcb,
            self.current,
            self.committed,
            self.launch_tcb,
            self.signature
        )
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for (&Chain, &AttestationReport) {
    type Output = ();

    fn verify(self) -> io::Result<Self::Output> {
        let vek = self.0.verify()?;

        let sig = EcdsaSig::try_from(&self.1.signature)?;

        let mut raw_report_bytes: Vec<u8> = Vec::with_capacity(1184usize);
        self.1.write_bytes(&mut raw_report_bytes)?;

        let measurable_bytes: &[u8] = &raw_report_bytes[..0x2a0];

        let mut hasher = Sha384::new();
        hasher.update(measurable_bytes);
        let base_digest = hasher.finish();

        let ec = vek.public_key()?.ec_key()?;
        let signed = sig.verify(&base_digest, &ec)?;
        match signed {
            true => Ok(()),
            false => Err(Error::new(
                ErrorKind::Other,
                "VEK does not sign the attestation report",
            )),
        }
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for (&Certificate, &AttestationReport) {
    type Output = ();

    fn verify(self) -> io::Result<Self::Output> {
        let vek = self.0;

        let sig = EcdsaSig::try_from(&self.1.signature)?;
        let mut raw_report_bytes: Vec<u8> = Vec::with_capacity(1184usize);
        self.1.write_bytes(&mut raw_report_bytes).unwrap();

        let measurable_bytes: &[u8] = &raw_report_bytes[..0x2a0];

        let mut hasher = Sha384::new();
        hasher.update(measurable_bytes);
        let base_digest = hasher.finish();

        let ec = vek.public_key()?.ec_key()?;
        let signed = sig.verify(&base_digest, &ec)?;
        match signed {
            true => Ok(()),
            false => Err(Error::new(
                ErrorKind::Other,
                "VEK does not sign the attestation report",
            )),
        }
    }
}

#[cfg(feature = "crypto_nossl")]
impl Verifiable for (&Chain, &AttestationReport) {
    type Output = ();

    fn verify(self) -> io::Result<Self::Output> {
        // According to Chapter 3 of the Versioned Chip Endorsement Key (VCEK) Certificate and the Versioned Loaded Endorsement Key (VLEK)
        // Certificate specifications, both Versioned Endorsement Key certificates certify an ECDSA public key on curve P-384,
        // with the signature hash algorithm being SHA-384.

        let vek = self.0.verify()?;

        let sig = p384::ecdsa::Signature::try_from(&self.1.signature)?;

        let mut raw_report_bytes: Vec<u8> = Vec::with_capacity(1184usize);
        self.1.write_bytes(&mut raw_report_bytes).unwrap();

        let measurable_bytes: &[u8] = &raw_report_bytes[..0x2a0];

        use sha2::Digest;
        let base_digest = sha2::Sha384::new_with_prefix(measurable_bytes);
        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(vek.public_key_sec1())
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("failed to deserialize public key from sec1 bytes: {e:?}"),
                )
            })?;
        use p384::ecdsa::signature::DigestVerifier;
        verifying_key.verify_digest(base_digest, &sig).map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("VEK does not sign the attestation report: {e:?}"),
            )
        })
    }
}

#[cfg(feature = "crypto_nossl")]
impl Verifiable for (&Certificate, &AttestationReport) {
    type Output = ();

    fn verify(self) -> io::Result<Self::Output> {
        // According to Chapter 3 of the [Versioned Chip Endorsement Key (VCEK) Certificate and
        // KDS Interface Specification][spec], the VCEK certificate certifies an ECDSA public key on curve P-384,
        // and the signature hash algorithm is sha384.
        // [spec]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf

        let vek = self.0;

        let sig = p384::ecdsa::Signature::try_from(&self.1.signature)?;

        let mut raw_report_bytes: Vec<u8> = Vec::with_capacity(1184usize);
        self.1.write_bytes(&mut raw_report_bytes).unwrap();

        let measurable_bytes: &[u8] = &raw_report_bytes[..0x2a0];

        use sha2::Digest;
        let base_digest = sha2::Sha384::new_with_prefix(measurable_bytes);
        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(vek.public_key_sec1())
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("failed to deserialize public key from sec1 bytes: {e:?}"),
                )
            })?;
        use p384::ecdsa::signature::DigestVerifier;
        verifying_key.verify_digest(base_digest, &sig).map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("VEK does not sign the attestation report: {e:?}"),
            )
        })
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
    /// | 63:25  | -                 | Reserved. MBZ.                                                                                                     >
    ///
    #[repr(C)]
    #[derive(Deserialize, Clone, Copy, Eq, PartialEq, Serialize, PartialOrd, Ord)]
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
}

impl Default for GuestPolicy {
    fn default() -> Self {
        Self(ByteParser::default())
    }
}

impl ByteParser for GuestPolicy {
    type Bytes = [u8; 8];

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self(u64::from_le_bytes(bytes))
    }

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }

    fn default() -> Self {
        Self(Default::default())
    }
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
  Single Socket: {}"#,
            self.0,
            self.abi_major(),
            self.abi_minor(),
            self.smt_allowed(),
            self.migrate_ma_allowed(),
            self.debug_allowed(),
            self.single_socket_required()
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
    /// Bits 5-63 are reserved.
    #[repr(C)]
    #[derive(Deserialize, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
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
  Alias Check Complete:      {}"#,
            self.0,
            self.smt_enabled(),
            self.tsme_enabled(),
            self.ecc_enabled(),
            self.rapl_disabled(),
            self.ciphertext_hiding_enabled(),
            self.alias_check_complete()
        )
    }
}

impl Default for PlatformInfo {
    fn default() -> Self {
        Self(ByteParser::default())
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

impl ByteParser for PlatformInfo {
    type Bytes = [u8; 8];

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self(u64::from_le_bytes(bytes))
    }

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }

    fn default() -> Self {
        Self(Default::default())
    }
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
    #[derive(Deserialize, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Serialize)]
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

impl Default for KeyInfo {
    fn default() -> Self {
        Self(ByteParser::default())
    }
}

impl ByteParser for KeyInfo {
    type Bytes = [u8; 4];

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self(u32::from_le_bytes(bytes))
    }

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }

    fn default() -> Self {
        Self(Default::default())
    }
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

    use super::*;
    use std::{
        convert::TryInto,
        io::{ErrorKind, Write},
    };

    #[test]
    fn test_derive_key_new() {
        let expected: DerivedKey = DerivedKey {
            root_key_select: 0,
            _reserved_0: 0,
            guest_field_select: GuestFieldSelect(0),
            vmpl: 0,
            guest_svn: 0,
            tcb_version: 0,
        };

        let guest_field: GuestFieldSelect = GuestFieldSelect(0);

        let actual: DerivedKey = DerivedKey::new(false, guest_field, 0, 0, 0);

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
    fn test_attestation_report_fmt() {
        let expected: &str = r#"Attestation Report:

Version:                      0

Guest SVN:                    0

Guest Policy (0x0):
  ABI Major:     0
  ABI Minor:     0
  SMT Allowed:   false
  Migrate MA:    false
  Debug Allowed: false
  Single Socket: false

Family ID:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Image ID:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

VMPL:                         0

Signature Algorithm:          0

Current TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         None

Platform Info (0):
  SMT Enabled:               false
  TSME Enabled:              false
  ECC Enabled:               false
  RAPL Disabled:             false
  Ciphertext Hiding Enabled: false
  Alias Check Complete:      false

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
  FMC:         None

CPUID Family ID:              None

CPUID Model ID:               None

CPUID Stepping:               None

Chip ID:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Committed TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         None

Current Version:              0.0.0

Committed Version:            0.0.0

Launch TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         None

Signature:
  R:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
  S:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00"#;
        assert_eq!(expected, AttestationReport::default().to_string())
    }

    #[test]
    fn test_attestation_report_copy() {
        let expected: AttestationReport = AttestationReport::default();

        let copy: AttestationReport = expected;

        assert_eq!(expected, copy);
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
  Alias Check Complete:      false"#;
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

        // Test bincode
        let binary = bincode::serialize(&original).unwrap();
        let from_binary: PlatformInfo = bincode::deserialize(&binary).unwrap();
        assert_eq!(original, from_binary);
    }

    #[test]
    fn test_key_info_serialization() {
        let original = KeyInfo(0b11111);

        // Test bincode
        let binary = bincode::serialize(&original).unwrap();
        let from_binary: KeyInfo = bincode::deserialize(&binary).unwrap();
        assert_eq!(original, from_binary);
        assert!(from_binary.author_key_en());
        assert!(from_binary.mask_chip_key());
        assert_eq!(from_binary.signing_key(), 0b111);
    }

    #[test]
    fn test_guest_policy_serialization() {
        let mut original: GuestPolicy = Default::default();
        original.set_abi_major(2);
        original.set_abi_minor(1);
        original.set_smt_allowed(true);
        original.set_debug_allowed(true);

        // Test bincode
        let binary = bincode::serialize(&original).unwrap();
        let from_binary: GuestPolicy = bincode::deserialize(&binary).unwrap();
        assert_eq!(original, from_binary);
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
            bincode::deserialize(&bincode::serialize(&platform_info).unwrap()).unwrap()
        );
        assert_eq!(
            key_info,
            bincode::deserialize(&bincode::serialize(&key_info).unwrap()).unwrap()
        );
        assert_eq!(
            guest_policy,
            bincode::deserialize(&bincode::serialize(&guest_policy).unwrap()).unwrap()
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
        let key = DerivedKey::new(true, GuestFieldSelect(0xFF), 2, 3, 0x1234);
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
    fn test_attestation_report_fields() {
        let report: AttestationReport = AttestationReport {
            version: 2,
            guest_svn: 1,
            vmpl: 3,
            ..Default::default()
        };
        assert_eq!(report.version, 2);
        assert_eq!(report.guest_svn, 1);
        assert_eq!(report.vmpl, 3);
        assert_eq!(report.measurement, [0; 48].try_into().unwrap());
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
        let version = Version::from_bytes(bytes);
        assert_eq!(version, Version::new(3, 2, 1));

        // Test to_bytes
        let version = Version::new(4, 5, 6);
        let bytes = version.to_bytes();
        assert_eq!(bytes, [6, 5, 4]);

        // Test roundtrip
        let original = Version::new(7, 8, 9);
        let bytes = original.to_bytes();
        let roundtrip = Version::from_bytes(bytes);
        assert_eq!(original, roundtrip);

        // Test default
        assert_eq!(<Version as Default>::default(), Version::new(0, 0, 0));
    }

    #[test]
    fn test_attestation_report_from_bytes() {
        // Create a valid attestation report bytes minus one byte.
        let mut bytes: Vec<u8> = vec![0; 1183];

        // Push the version byte at the beginning.
        bytes.insert(0, 2);

        let vcek = [
            0xD4, 0x95, 0x54, 0xEC, 0x71, 0x7F, 0x4E, 0x5B, 0x0F, 0xE6, 0xB1, 0x43, 0xBC, 0xF0,
            0x40, 0x5B, 0xD7, 0xAE, 0x30, 0x47, 0x27, 0xED, 0xF4, 0x66, 0x03, 0xF2, 0xA7, 0x6A,
            0xEF, 0x6A, 0x3A, 0xBC, 0x15, 0xD7, 0xAF, 0x38, 0xDB, 0x75, 0x70, 0x39, 0x02, 0x9F,
            0x0E, 0xFA, 0xCF, 0xD0, 0x8E, 0x24, 0x43, 0x24, 0x88, 0x47, 0x38, 0xC7, 0x2B, 0x08,
            0x2E, 0x2F, 0x87, 0xA4, 0x4D, 0x54, 0x1E, 0xB6,
        ];

        bytes[0x1A8..0x1E0].copy_from_slice(&vcek[..(0x1E0 - 0x1A8)]);

        // Test valid input
        let result = AttestationReport::from_bytes(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_attestation_report_from_invalid_bytes() {
        // Create a valid attestation report bytes minus one byte.
        let mut bytes: Vec<u8> = vec![0; 1183];

        // Push the version byte at the beginning.
        bytes.insert(0, 2);

        // Test invalid input (too short)
        AttestationReport::from_bytes(&bytes[..100]).unwrap();
    }

    #[test]
    fn test_attestation_report_write_bytes() {
        let report = AttestationReport::default();
        let mut buffer = Vec::new();

        // Test successful write
        let result = report.write_bytes(&mut buffer);
        assert!(result.is_ok());

        // Test writing to a failing writer
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(ErrorKind::Other, "test error"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = FailingWriter;

        let result = report.write_bytes(FailingWriter);
        assert!(result.is_err());
        assert!(writer.flush().is_ok());
    }

    #[test]
    fn test_version_edge_cases() {
        // Test max values
        let version = Version::new(255, 255, 255);
        let bytes = version.to_bytes();
        assert_eq!(bytes, [255, 255, 255]);

        // Test mixed values
        let version = Version::new(0, 255, 0);
        let bytes = version.to_bytes();
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
        assert_eq!(original.to_bytes(), cloned.to_bytes());
    }

    #[test]
    fn test_attestation_report_complex_write() {
        let report = AttestationReport {
            version: 2,
            guest_svn: 1,
            policy: GuestPolicy::from(0xFF),
            family_id: [0xAA; 16].try_into().unwrap(),
            image_id: [0xBB; 16].try_into().unwrap(),
            chip_id: [
                0xD4, 0x95, 0x54, 0xEC, 0x71, 0x7F, 0x4E, 0x5B, 0x0F, 0xE6, 0xB1, 0x43, 0xBC, 0xF0,
                0x40, 0x5B, 0xD7, 0xAE, 0x30, 0x47, 0x27, 0xED, 0xF4, 0x66, 0x03, 0xF2, 0xA7, 0x6A,
                0xEF, 0x6A, 0x3A, 0xBC, 0x15, 0xD7, 0xAF, 0x38, 0xDB, 0x75, 0x70, 0x39, 0x02, 0x9F,
                0x0E, 0xFA, 0xCF, 0xD0, 0x8E, 0x24, 0x43, 0x24, 0x88, 0x47, 0x38, 0xC7, 0x2B, 0x08,
                0x2E, 0x2F, 0x87, 0xA4, 0x4D, 0x54, 0x1E, 0xB6,
            ]
            .try_into()
            .unwrap(),
            ..Default::default()
        };

        let mut buffer = Vec::new();
        assert!(report.write_bytes(&mut buffer).is_ok());

        // Read back and verify
        let read_back = AttestationReport::from_bytes(&buffer).unwrap();
        assert_eq!(read_back.version, 2);
        assert_eq!(read_back.guest_svn, 1);
        assert_eq!(read_back.family_id, Array([0xAA; 16]));
        assert_eq!(read_back.image_id, Array([0xBB; 16]));
    }

    #[test]
    fn test_write_with_limited_writer() {
        let report = AttestationReport::default();

        // Writer that can only write small chunks
        struct LimitedWriter {
            data: Vec<u8>,
            max_write: usize,
        }

        impl Write for LimitedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let write_size = std::cmp::min(self.max_write, buf.len());
                self.data.extend_from_slice(&buf[..write_size]);
                Ok(write_size)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = LimitedWriter {
            data: Vec::new(),
            max_write: 16, // Only write 16 bytes at a time
        };

        assert!(report.write_bytes(&mut writer).is_ok());
        assert!(writer.flush().is_ok());
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
    fn test_turin_like_chip_id_milan_chip_id() {
        // Valid Milan CHIP_ID
        let vcek_bytes = [
            0xD4, 0x95, 0x54, 0xEC, 0x71, 0x7F, 0x4E, 0x5B, 0x0F, 0xE6, 0xB1, 0x43, 0xBC, 0xF0,
            0x40, 0x5B, 0xD7, 0xAE, 0x30, 0x47, 0x27, 0xED, 0xF4, 0x66, 0x03, 0xF2, 0xA7, 0x6A,
            0xEF, 0x6A, 0x3A, 0xBC, 0x15, 0xD7, 0xAF, 0x38, 0xDB, 0x75, 0x70, 0x39, 0x02, 0x9F,
            0x0E, 0xFA, 0xCF, 0xD0, 0x8E, 0x24, 0x43, 0x24, 0x88, 0x47, 0x38, 0xC7, 0x2B, 0x08,
            0x2E, 0x2F, 0x87, 0xA4, 0x4D, 0x54, 0x1E, 0xB6,
        ];

        assert!(!AttestationReport::chip_id_is_turin_like(&vcek_bytes).unwrap());
    }

    #[test]
    fn test_turin_like_chip_id_turin_chip_id() {
        // Valid Turin CHIP_ID
        let vcek_bytes = [
            0xD4, 0x95, 0x54, 0xEC, 0x71, 0x7F, 0x4E, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert!(AttestationReport::chip_id_is_turin_like(&vcek_bytes).unwrap());
    }
}
