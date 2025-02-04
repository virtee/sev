// SPDX-License-Identifier: Apache-2.0

use crate::error::AttestationReportError;
use crate::{certs::snp::ecdsa::Signature, firmware::host::TcbVersion, util::hexdump};

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use crate::certs::snp::{Certificate, Chain, Verifiable};

use crate::util::sealed;
use bitfield::bitfield;
use serde::{Deserialize, Serialize, Serializer};
use serde_big_array::BigArray;
use std::convert::{TryFrom, TryInto};

use std::fmt::Display;

// #[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use std::io::{self, Error, ErrorKind};

#[cfg(feature = "openssl")]
use openssl::{ecdsa::EcdsaSig, sha::Sha384};

/// Structure of required data for fetching the derived key.
#[derive(Copy, Clone, Debug)]
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
    #[derive(Default, Copy, Clone)]
    pub struct GuestFieldSelect(u64);
    impl Debug;
    /// Check/Set guest policy inclusion in derived key.
    pub get_guest_policy, set_guest_policy: 0, 0;
    /// Check/Set image id inclusion in derived key.
    pub get_image_id, set_image_id: 1, 1;
    /// Check/Set family id inclusion in derived key.
    pub get_family_id, set_family_id: 2, 2;
    /// Check/Set measurement inclusion in derived key.
    pub get_measurement, set_measurement: 3, 3;
    /// Check/Set svn inclusion in derived key.
    pub get_svn, set_svn: 4, 4;
    /// Check/Set tcb version inclusion in derived key.
    pub get_tcb_version, set_tcb_version: 5, 5;
}

/// Trait shared between attestation reports to be able to verify them against the VEK.
pub trait Attestable: Serialize + sealed::Sealed {
    /// Serialize the provided Attestation Report and get the measurable bytes from it
    fn measurable_bytes(&self) -> io::Result<Vec<u8>> {
        let measurable_bytes: &[u8] = &bincode::serialize(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Unable to serialize bytes: {}", e),
            )
        })?;
        Ok(measurable_bytes[..0x2a0].to_vec())
    }
    /// Get the attestation report signature
    fn signature(&self) -> &Signature;
}

/// The guest can request that the firmware construct an attestation report. External entities can use an
/// attestation report to assure the identity and security configuration of the guest.
///
/// A guest requests an attestation report by constructing an MSGReportReq
/// The message contains data provided by the guest in REPORT_DATA to be included
/// into the report; the firmware does not interpret this data.
///
/// Upon receiving a request for an attestation report, the PSP creates one.
///
/// The firmware generates a report ID for each guest that persists with the guest instance throughout
/// its lifetime. In each attestation report, the report ID is placed in REPORT_ID. If the guest has a
/// migration agent associated with it, the REPORT_ID_MA is filled in with the report ID of the
/// migration agent.
///
/// The firmware signs the attestation report with its VEK (VCEK or VLEK). The firmware uses the system wide
/// ReportedTcb value as the TCB version to derive the VCEK. This value is set by the hypervisor.
/// The VLEK is generated externally and has to be loaded into the machine.
///
/// The firmware guarantees that the ReportedTcb value is never greater than the installed TCB
/// version
///
/// Since the release of the 1.56 ABI, the Attestation Report was bumped from version 2 to 3.
/// Due to content differences, both versions are kept separately in order to provide backwards compatibility and most reliable security.
#[derive(Debug, Clone, Copy)]
pub enum AttestationReport {
    /// Version 2 of the Attestation Report
    V2(AttestationReportV2),
    /// Version 3 of the Attestation Report
    V3(AttestationReportV3),
}

impl TryFrom<&[u8]> for AttestationReport {
    type Error = AttestationReportError;

    fn try_from(raw_report: &[u8]) -> Result<Self, Self::Error> {
        let version =
            u32::from_le_bytes([raw_report[0], raw_report[1], raw_report[2], raw_report[3]]);
        // Return the appropriate report version
        match version {
            2 => {
                let report_v2: AttestationReportV2 = raw_report.try_into()?;
                Ok(AttestationReport::V2(report_v2))
            }
            3 => {
                let report_v3: AttestationReportV3 = raw_report.try_into()?;
                Ok(AttestationReport::V3(report_v3))
            }
            _ => Err(AttestationReportError::UnsupportedReportVersion(version))?,
        }
    }
}

/// Implement custom serialization for AttestationReport
/// This will ensure that the Attestation Report enum gets serialized into raw bytes,
/// not the serde default that tags the enum with 4 extra bytes for its own tagging mechanism.
impl Serialize for AttestationReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AttestationReport::V2(report) => report.serialize(serializer),
            AttestationReport::V3(report) => report.serialize(serializer),
        }
    }
}

impl sealed::Sealed for AttestationReport {}

impl Attestable for AttestationReport {
    fn measurable_bytes(&self) -> io::Result<Vec<u8>> {
        //Return measurable bytes for the report
        match self {
            Self::V2(v2) => Ok(v2.measurable_bytes()?),

            Self::V3(v3) => Ok(v3.measurable_bytes()?),
        }
    }
    fn signature(&self) -> &Signature {
        match self {
            Self::V2(v2) => v2.signature(),
            Self::V3(v3) => v3.signature(),
        }
    }
}

impl AttestationReport {
    /// Convert bytes to an Attestation Report Enum
    pub fn from_bytes(bytes: &[u8]) -> Result<AttestationReport, AttestationReportError> {
        AttestationReport::try_from(bytes)
    }

    /// Serialize the Attestation Report enum to raw bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, AttestationReportError> {
        bincode::serialize(self).map_err(|e| AttestationReportError::BincodeError(*e))
    }
    /// Get Attestation Report Version
    pub fn version(&self) -> u32 {
        match self {
            Self::V2(report) => report.version,
            Self::V3(report) => report.version,
        }
    }

    /// Get the guest SVN
    pub fn guest_svn(&self) -> u32 {
        match self {
            Self::V2(report) => report.guest_svn,
            Self::V3(report) => report.guest_svn,
        }
    }
    /// Get the guest policy.
    pub fn policy(&self) -> GuestPolicy {
        match self {
            Self::V2(report) => report.policy,
            Self::V3(report) => report.policy,
        }
    }

    /// Get Family ID
    pub fn family_id(&self) -> [u8; 16] {
        match self {
            Self::V2(report) => report.family_id,
            Self::V3(report) => report.family_id,
        }
    }
    /// Get Image ID
    pub fn image_id(&self) -> [u8; 16] {
        match self {
            Self::V2(report) => report.image_id,
            Self::V3(report) => report.image_id,
        }
    }

    /// Get request VMPL for the attestation report.
    pub fn vmpl(&self) -> u32 {
        match self {
            Self::V2(report) => report.vmpl,
            Self::V3(report) => report.vmpl,
        }
    }
    /// Get signature alorithm used to sign this report
    pub fn sig_algo(&self) -> u32 {
        match self {
            Self::V2(report) => report.sig_algo,
            Self::V3(report) => report.sig_algo,
        }
    }

    /// Get current TCB
    pub fn current_tcb(&self) -> TcbVersion {
        match self {
            Self::V2(report) => report.current_tcb,
            Self::V3(report) => report.current_tcb,
        }
    }

    /// Get Platform Info
    pub fn plat_info(&self) -> PlatformInfo {
        match self {
            Self::V2(report) => PlatformInfo::V1(report.plat_info),
            Self::V3(report) => PlatformInfo::V2(report.plat_info),
        }
    }

    /// Get Key Information
    pub fn key_info(&self) -> KeyInfo {
        match self {
            Self::V2(report) => report.key_info,
            Self::V3(report) => report.key_info,
        }
    }

    /// Get the guest provided report data
    pub fn report_data(&self) -> [u8; 64] {
        match self {
            Self::V2(report) => report.report_data,
            Self::V3(report) => report.report_data,
        }
    }

    /// Get the measurement calculated at launch.
    pub fn measurement(&self) -> [u8; 48] {
        match self {
            Self::V2(report) => report.measurement,
            Self::V3(report) => report.measurement,
        }
    }

    /// Get data provided by the hypervisor at launch.
    pub fn host_data(&self) -> [u8; 32] {
        match self {
            Self::V2(report) => report.host_data,
            Self::V3(report) => report.host_data,
        }
    }

    /// Get the SHA-384 digest of the ID public key that signed the ID block.
    pub fn id_key_digest(&self) -> [u8; 48] {
        match self {
            Self::V2(report) => report.id_key_digest,
            Self::V3(report) => report.id_key_digest,
        }
    }

    /// Get the SHA-384 digest of the author public key that certified the ID key,.
    pub fn author_key_digest(&self) -> [u8; 48] {
        match self {
            Self::V2(report) => report.author_key_digest,
            Self::V3(report) => report.author_key_digest,
        }
    }

    /// Get report ID of this guest
    pub fn report_id(&self) -> [u8; 32] {
        match self {
            Self::V2(report) => report.report_id,
            Self::V3(report) => report.report_id,
        }
    }

    /// Get report ID of this guest's migration agent (if applicable).
    pub fn report_id_ma(&self) -> [u8; 32] {
        match self {
            Self::V2(report) => report.report_id_ma,
            Self::V3(report) => report.report_id_ma,
        }
    }

    /// Get the Reported TCB of the report
    pub fn reported_tcb(&self) -> TcbVersion {
        match self {
            Self::V2(report) => report.reported_tcb,
            Self::V3(report) => report.reported_tcb,
        }
    }

    /// Get the CPUID info from the report (V3 only)
    pub fn cpuid(&self) -> Result<(u8, u8, u8), AttestationReportError> {
        match self {
            Self::V2(_) => Err(AttestationReportError::UnsupportedField(
                "cpuid information".to_string(),
            )),
            Self::V3(report) => Ok((report.cpuid_fam_id, report.cpuid_mod_id, report.cpuid_step)),
        }
    }

    /// Get the CHIP ID of the attestation report
    pub fn chip_id(&self) -> [u8; 64] {
        match self {
            Self::V2(report) => report.chip_id,
            Self::V3(report) => report.chip_id,
        }
    }

    /// Get commited TCB
    pub fn commited_tcb(&self) -> TcbVersion {
        match self {
            Self::V2(report) => report.committed_tcb,
            Self::V3(report) => report.committed_tcb,
        }
    }

    /// Get the current version in the report (major,minor,build)
    pub fn current_version(&self) -> (u8, u8, u8) {
        match self {
            Self::V2(report) => (
                report.current_major,
                report.current_minor,
                report.current_build,
            ),
            Self::V3(report) => (
                report.current_major,
                report.current_minor,
                report.current_build,
            ),
        }
    }

    /// Get the committed version in the report (major,minor,build)
    pub fn commited_version(&self) -> (u8, u8, u8) {
        match self {
            Self::V2(report) => (
                report.committed_major,
                report.committed_minor,
                report.committed_build,
            ),
            Self::V3(report) => (
                report.committed_major,
                report.committed_minor,
                report.committed_build,
            ),
        }
    }

    /// Get launch TCB
    pub fn launch_tcb(&self) -> TcbVersion {
        match self {
            Self::V2(report) => report.launch_tcb,
            Self::V3(report) => report.launch_tcb,
        }
    }
}

impl Display for AttestationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationReport::V2(report) => write!(f, "{}", report),
            AttestationReport::V3(report) => write!(f, "{}", report),
        }
    }
}

/// Version 2 of the attestation report
/// The first upstream supported attestation report
/// Systems that contain firmware prior to the spec release 1.56 will use this attestation report.
#[repr(C)]
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct AttestationReportV2 {
    /// Version number of this attestation report. Set to 2h for this specification.
    pub version: u32,
    /// The guest SVN.
    pub guest_svn: u32,
    /// The guest policy.
    pub policy: GuestPolicy,
    /// The family ID provided at launch.
    pub family_id: [u8; 16],
    /// The image ID provided at launch.
    pub image_id: [u8; 16],
    /// The request VMPL for the attestation report.
    pub vmpl: u32,
    /// The signature algorithm used to sign this report.
    pub sig_algo: u32,
    /// Current TCB. See SNPTcbVersion
    pub current_tcb: TcbVersion,
    /// Information about the platform. See PlatformInfo
    pub plat_info: PlatformInfoV1,
    /// Information related to signing keys in the report. See KeyInfo
    pub key_info: KeyInfo,
    _reserved_0: u32,
    #[serde(with = "BigArray")]
    /// Guest-provided 512 Bits of Data
    pub report_data: [u8; 64],
    #[serde(with = "BigArray")]
    /// The measurement calculated at launch.
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32],
    #[serde(with = "BigArray")]
    /// SHA-384 digest of the ID public key that signed the ID block provided
    /// in SNP_LANUNCH_FINISH.
    pub id_key_digest: [u8; 48],
    #[serde(with = "BigArray")]
    /// SHA-384 digest of the Author public key that certified the ID key,
    /// if provided in SNP_LAUNCH_FINSIH. Zeroes if AUTHOR_KEY_EN is 1.
    pub author_key_digest: [u8; 48],
    /// Report ID of this guest.
    pub report_id: [u8; 32],
    /// Report ID of this guest's migration agent (if applicable).
    pub report_id_ma: [u8; 32],
    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: TcbVersion,
    _reserved_1: [u8; 24],
    #[serde(with = "BigArray")]
    /// If MaskChipId is set to 0, Identifier unique to the chip.
    /// Otherwise set to 0h.
    pub chip_id: [u8; 64],
    /// CommittedTCB
    pub committed_tcb: TcbVersion,
    /// The build number of CurrentVersion
    pub current_build: u8,
    /// The minor number of CurrentVersion
    pub current_minor: u8,
    /// The major number of CurrentVersion
    pub current_major: u8,
    _reserved_2: u8,
    /// The build number of CommittedVersion
    pub committed_build: u8,
    /// The minor number of CommittedVersion
    pub committed_minor: u8,
    /// The major number of CommittedVersion
    pub committed_major: u8,
    _reserved_3: u8,
    /// The CurrentTcb at the time the guest was launched or imported.
    pub launch_tcb: TcbVersion,
    #[serde(with = "BigArray")]
    _reserved_4: [u8; 168],
    /// Signature of bytes 0 to 0x29F inclusive of this report.
    /// The format of the signature is found within Signature.
    pub signature: Signature,
}

impl Default for AttestationReportV2 {
    fn default() -> Self {
        Self {
            version: Default::default(),
            guest_svn: Default::default(),
            policy: Default::default(),
            family_id: Default::default(),
            image_id: Default::default(),
            vmpl: Default::default(),
            sig_algo: Default::default(),
            current_tcb: Default::default(),
            plat_info: Default::default(),
            key_info: Default::default(),
            _reserved_0: Default::default(),
            report_data: [0; 64],
            measurement: [0; 48],
            host_data: Default::default(),
            id_key_digest: [0; 48],
            author_key_digest: [0; 48],
            report_id: Default::default(),
            report_id_ma: Default::default(),
            reported_tcb: Default::default(),
            _reserved_1: Default::default(),
            chip_id: [0; 64],
            committed_tcb: Default::default(),
            current_build: Default::default(),
            current_minor: Default::default(),
            current_major: Default::default(),
            _reserved_2: Default::default(),
            committed_build: Default::default(),
            committed_minor: Default::default(),
            committed_major: Default::default(),
            _reserved_3: Default::default(),
            launch_tcb: Default::default(),
            _reserved_4: [0; 168],
            signature: Default::default(),
        }
    }
}

impl Display for AttestationReportV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Attestation Report ({} bytes):
Version:                      {}
Guest SVN:                    {}
{}
Family ID:                    {}
Image ID:                     {}
VMPL:                         {}
Signature Algorithm:          {}
Current TCB:
{}
{}
{}
Report Data:                  {}
Measurement:                  {}
Host Data:                    {}
ID Key Digest:                {}
Author Key Digest:            {}
Report ID:                    {}
Report ID Migration Agent:    {}
Reported TCB:                 {}
Chip ID:                      {}
Committed TCB:
{}
Current Build:                {}
Current Minor:                {}
Current Major:                {}
Committed Build:              {}
Committed Minor:              {}
Committed Major:              {}
Launch TCB:
{}
{}
"#,
            std::mem::size_of_val(self),
            self.version,
            self.guest_svn,
            self.policy,
            hexdump(&self.family_id),
            hexdump(&self.image_id),
            self.vmpl,
            self.sig_algo,
            self.current_tcb,
            self.plat_info,
            self.key_info,
            hexdump(&self.report_data),
            hexdump(&self.measurement),
            hexdump(&self.host_data),
            hexdump(&self.id_key_digest),
            hexdump(&self.author_key_digest),
            hexdump(&self.report_id),
            hexdump(&self.report_id_ma),
            self.reported_tcb,
            hexdump(&self.chip_id),
            self.committed_tcb,
            self.current_build,
            self.current_minor,
            self.current_major,
            self.committed_build,
            self.committed_minor,
            self.committed_major,
            self.launch_tcb,
            self.signature
        )
    }
}

impl sealed::Sealed for AttestationReportV2 {}

impl Attestable for AttestationReportV2 {
    fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl TryFrom<&[u8]> for AttestationReportV2 {
    type Error = AttestationReportError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(bytes).map_err(|e| AttestationReportError::BincodeError(*e))
    }
}

/// Version 3 of the attestation report
/// Systems that contain firmware starting from the spec release 1.56 will use this attestation report.
/// This version adds:
/// The CPUID Family, Model and Stepping fields
/// The Alias_Check_Complete field in the PlatformInfo field
#[repr(C)]
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct AttestationReportV3 {
    /// Version number of this attestation report. Set to 2h for this specification.
    pub version: u32,
    /// The guest SVN.
    pub guest_svn: u32,
    /// The guest policy.
    pub policy: GuestPolicy,
    /// The family ID provided at launch.
    pub family_id: [u8; 16],
    /// The image ID provided at launch.
    pub image_id: [u8; 16],
    /// The request VMPL for the attestation report.
    pub vmpl: u32,
    /// The signature algorithm used to sign this report.
    pub sig_algo: u32,
    /// Current TCB. See SNPTcbVersion
    pub current_tcb: TcbVersion,
    /// Information about the platform. See PlatformInfo
    pub plat_info: PlatformInfoV2,
    /// Information related to signing keys in the report. See KeyInfo
    pub key_info: KeyInfo,
    _reserved_0: u32,
    #[serde(with = "BigArray")]
    /// Guest-provided 512 Bits of Data
    pub report_data: [u8; 64],
    #[serde(with = "BigArray")]
    /// The measurement calculated at launch.
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32],
    #[serde(with = "BigArray")]
    /// SHA-384 digest of the ID public key that signed the ID block provided
    /// in SNP_LANUNCH_FINISH.
    pub id_key_digest: [u8; 48],
    #[serde(with = "BigArray")]
    /// SHA-384 digest of the Author public key that certified the ID key,
    /// if provided in SNP_LAUNCH_FINSIH. Zeroes if AUTHOR_KEY_EN is 1.
    pub author_key_digest: [u8; 48],
    /// Report ID of this guest.
    pub report_id: [u8; 32],
    /// Report ID of this guest's migration agent (if applicable).
    pub report_id_ma: [u8; 32],
    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: TcbVersion,
    /// CPUID Familiy ID (Combined Extended Family ID and Family ID)
    pub cpuid_fam_id: u8,
    /// CPUID Model (Combined Extended Model and Model fields)
    pub cpuid_mod_id: u8,
    /// CPUID Stepping
    pub cpuid_step: u8,
    _reserved_1: [u8; 21],
    #[serde(with = "BigArray")]
    /// If MaskChipId is set to 0, Identifier unique to the chip.
    /// Otherwise set to 0h.
    pub chip_id: [u8; 64],
    /// CommittedTCB
    pub committed_tcb: TcbVersion,
    /// The build number of CurrentVersion
    pub current_build: u8,
    /// The minor number of CurrentVersion
    pub current_minor: u8,
    /// The major number of CurrentVersion
    pub current_major: u8,
    _reserved_2: u8,
    /// The build number of CommittedVersion
    pub committed_build: u8,
    /// The minor number of CommittedVersion
    pub committed_minor: u8,
    /// The major number of CommittedVersion
    pub committed_major: u8,
    _reserved_3: u8,
    /// The CurrentTcb at the time the guest was launched or imported.
    pub launch_tcb: TcbVersion,
    #[serde(with = "BigArray")]
    _reserved_4: [u8; 168],
    /// Signature of bytes 0 to 0x29F inclusive of this report.
    /// The format of the signature is found within Signature.
    pub signature: Signature,
}

impl Default for AttestationReportV3 {
    fn default() -> Self {
        Self {
            version: Default::default(),
            guest_svn: Default::default(),
            policy: Default::default(),
            family_id: Default::default(),
            image_id: Default::default(),
            vmpl: Default::default(),
            sig_algo: Default::default(),
            current_tcb: Default::default(),
            plat_info: Default::default(),
            key_info: Default::default(),
            _reserved_0: Default::default(),
            report_data: [0; 64],
            measurement: [0; 48],
            host_data: Default::default(),
            id_key_digest: [0; 48],
            author_key_digest: [0; 48],
            report_id: Default::default(),
            report_id_ma: Default::default(),
            reported_tcb: Default::default(),
            cpuid_fam_id: Default::default(),
            cpuid_mod_id: Default::default(),
            cpuid_step: Default::default(),
            _reserved_1: Default::default(),
            chip_id: [0; 64],
            committed_tcb: Default::default(),
            current_build: Default::default(),
            current_minor: Default::default(),
            current_major: Default::default(),
            _reserved_2: Default::default(),
            committed_build: Default::default(),
            committed_minor: Default::default(),
            committed_major: Default::default(),
            _reserved_3: Default::default(),
            launch_tcb: Default::default(),
            _reserved_4: [0; 168],
            signature: Default::default(),
        }
    }
}

impl Display for AttestationReportV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Attestation Report ({} bytes):
Version:                      {}
Guest SVN:                    {}
{}
Family ID:                    {}
Image ID:                     {}
VMPL:                         {}
Signature Algorithm:          {}
Current TCB:
{}
{}
{}
Report Data:                  {}
Measurement:                  {}
Host Data:                    {}
ID Key Digest:                {}
Author Key Digest:            {}
Report ID:                    {}
Report ID Migration Agent:    {}
Reported TCB:                 {}
CPUID Family ID:              {}
CPUID Model ID:               {}
CPUID Stepping:               {}
Chip ID:                      {}
Committed TCB:
{}
Current Build:                {}
Current Minor:                {}
Current Major:                {}
Committed Build:              {}
Committed Minor:              {}
Committed Major:              {}
Launch TCB:
{}
{}
"#,
            std::mem::size_of_val(self),
            self.version,
            self.guest_svn,
            self.policy,
            hexdump(&self.family_id),
            hexdump(&self.image_id),
            self.vmpl,
            self.sig_algo,
            self.current_tcb,
            self.plat_info,
            self.key_info,
            hexdump(&self.report_data),
            hexdump(&self.measurement),
            hexdump(&self.host_data),
            hexdump(&self.id_key_digest),
            hexdump(&self.author_key_digest),
            hexdump(&self.report_id),
            hexdump(&self.report_id_ma),
            self.reported_tcb,
            self.cpuid_fam_id,
            self.cpuid_mod_id,
            self.cpuid_step,
            hexdump(&self.chip_id),
            self.committed_tcb,
            self.current_build,
            self.current_minor,
            self.current_major,
            self.committed_build,
            self.committed_minor,
            self.committed_major,
            self.launch_tcb,
            self.signature
        )
    }
}

impl sealed::Sealed for AttestationReportV3 {}

impl Attestable for AttestationReportV3 {
    fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl TryFrom<&[u8]> for AttestationReportV3 {
    type Error = AttestationReportError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(bytes).map_err(|e| AttestationReportError::BincodeError(*e))
    }
}

#[cfg(feature = "openssl")]
impl<T> Verifiable for (&Chain, &T)
where
    T: Attestable,
{
    type Output = ();

    fn verify(self) -> io::Result<Self::Output> {
        let vek = self.0.verify()?;

        let sig = EcdsaSig::try_from(self.1.signature())?;
        let measurable_bytes = self.1.measurable_bytes()?;

        let mut hasher = Sha384::new();
        hasher.update(&measurable_bytes);
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
impl<T> Verifiable for (&Certificate, &T)
where
    T: Attestable,
{
    type Output = ();

    fn verify(self) -> io::Result<Self::Output> {
        let vek = self.0;

        let sig = EcdsaSig::try_from(self.1.signature())?;
        let measurable_bytes = self.1.measurable_bytes()?;

        let mut hasher = Sha384::new();
        hasher.update(&measurable_bytes);
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
impl<T> Verifiable for (&Chain, &T)
where
    T: Attestable,
{
    type Output = ();

    fn verify(self) -> io::Result<Self::Output> {
        // According to Chapter 3 of the Versioned Chip Endorsement Key (VCEK) Certificate and the Versioned Loaded Endorsement Key (VLEK)
        // Certificate specifications, both Versioned Endorsement Key certificates certify an ECDSA public key on curve P-384,
        // with the signature hash algorithm being SHA-384.

        let vek = self.0.verify()?;

        let sig = p384::ecdsa::Signature::try_from(self.1.signature())?;

        let measurable_bytes = self.1.measurable_bytes()?;

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
impl<T> Verifiable for (&Certificate, &T)
where
    T: Attestable,
{
    type Output = ();

    fn verify(self) -> io::Result<Self::Output> {
        // According to Chapter 3 of the [Versioned Chip Endorsement Key (VCEK) Certificate and
        // KDS Interface Specification][spec], the VCEK certificate certifies an ECDSA public key on curve P-384,
        // and the signature hash algorithm is sha384.
        // [spec]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf

        let vek = self.0;

        let sig = p384::ecdsa::Signature::try_from(self.1.signature())?;

        let measurable_bytes = self.1.measurable_bytes()?;

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
    #[derive(Default, Deserialize, Clone, Copy, Eq, PartialEq, Serialize)]
    pub struct GuestPolicy(u64);
    impl Debug;
    /// ABI_MINOR field: Indicates the minor API version.
    pub abi_minor, set_abi_minor: 7, 0;
    /// ABI_MAJOR field: Indicates the minor API version.
    pub abi_major, set_abi_major: 15, 8;
    /// SMT_ALLOWED field: Indicates the if SMT should be permitted.
    pub smt_allowed, set_smt_allowed: 16, 16;
    /// MIGRATE_MA_ALLOWED field: Indicates the if migration is permitted with
    /// the migration agent.
    pub migrate_ma_allowed, set_migrate_ma_allowed: 18, 18;
    /// DEBUG_ALLOWED field: Indicates the if debugging should is permitted.
    pub debug_allowed, set_debug_allowed: 19, 19;
    /// SINGLE_SOCKET_REQUIRED field: Indicates the if a single socket is required.
    pub single_socket_required, set_single_socket_required: 20, 20;
    /// CXL_ALLOW field: (1) can populate CXL devices/memory, (0) cannot populate CXL devices/memory
    pub cxl_allowed, set_cxl_allowed: 21, 21;
    /// MEM_AES_256_XTS field: (1) require AES 256 XTS encryption, (0) allows either AES 128 XEX or AES 256 XTS encryption
    pub mem_aes_256_xts, set_mem_aes_256_xts: 22, 22;
    /// RAPL_DIS field: (1) RAPL must be disabled, (0) allow RAPL
    pub rapl_dis, set_rapl_dis: 23, 23;
    /// CIPHERTEXT_HIDING field: (1) ciphertext hiding must be enabled, (0) ciphertext hiding may be enabled/disabled
    pub ciphertext_hiding, set_ciphertext_hiding: 24, 24;
}

impl Display for GuestPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
    Guest Policy (0x{:x}):
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

/// Enum Containing the different versions of the Platform Info Bitfield
pub enum PlatformInfo {
    /// Version 1 of Platform Info
    V1(PlatformInfoV1),
    /// Version 2 of Platform Info
    V2(PlatformInfoV2),
}

impl PlatformInfo {
    /// Get SMT enablement status
    pub fn smt_enabled(&self) -> u64 {
        match self {
            Self::V1(field) => field.smt_enabled(),
            Self::V2(field) => field.smt_enabled(),
        }
    }

    /// Get TSME enablement status
    pub fn tsme_enabled(&self) -> u64 {
        match self {
            Self::V1(field) => field.tsme_enabled(),
            Self::V2(field) => field.tsme_enabled(),
        }
    }
    /// Get ECC memory status
    pub fn ecc_enabled(&self) -> u64 {
        match self {
            Self::V1(field) => field.ecc_enabled(),
            Self::V2(field) => field.ecc_enabled(),
        }
    }

    /// Get RAPL enablement status
    pub fn rapl_disabled(&self) -> u64 {
        match self {
            Self::V1(field) => field.rapl_disabled(),
            Self::V2(field) => field.rapl_disabled(),
        }
    }

    /// Get cyphertext hiding status
    pub fn cypertext_hiding_enabled(&self) -> u64 {
        match self {
            Self::V1(field) => field.ciphertext_hiding_enabled(),
            Self::V2(field) => field.ciphertext_hiding_enabled(),
        }
    }

    /// Get alias check complete
    pub fn alias_check_complete(&self) -> Result<u64, AttestationReportError> {
        match self {
            Self::V1(_) => Err(AttestationReportError::UnsupportedField(
                "Alias Check Complete".to_string(),
            )),
            Self::V2(field) => Ok(field.alias_check_complete()),
        }
    }
}

bitfield! {
    /// Version 1 PlatformInfo bitfield
    /// A structure with a bit-field unsigned 64 bit integer:
    /// Bit 0 representing the status of SMT enablement.
    /// Bit 1 representing the status of TSME enablement.
    /// Bit 2 indicates if ECC memory is used.
    /// Bit 3 indicates if RAPL is disabled.
    /// Bit 4 indicates if ciphertext hiding is enabled
    /// Bits 5-63 are reserved.
    #[repr(C)]
    #[derive(Default, Deserialize, Clone, Copy, Serialize)]
    pub struct PlatformInfoV1(u64);
    impl Debug;
    /// Returns the bit state of SMT
    pub smt_enabled, _: 0, 0;
    /// Returns the bit state of TSME.
    pub tsme_enabled, _: 1, 1;
    /// Indicates that the platform is currently using ECC memory
    pub ecc_enabled, _: 2, 2;
    /// Indicates that the RAPL feature is disabled
    pub rapl_disabled, _: 3, 3;
    /// Indicates that ciphertext hiding is enabled
    pub ciphertext_hiding_enabled, _: 4, 4;
    /// reserved
    reserved, _: 5, 63;
}

impl Display for PlatformInfoV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Platform Info ({}):
  SMT Enabled:               {}
  TSME Enabled:              {}
  ECC Enabled:               {}
  RAPL Disabled:             {}
  Ciphertext Hiding Enabled: {}
"#,
            self.0,
            self.smt_enabled(),
            self.tsme_enabled(),
            self.ecc_enabled(),
            self.rapl_disabled(),
            self.ciphertext_hiding_enabled(),
        )
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
    #[derive(Default, Deserialize, Clone, Copy, Serialize)]
    pub struct PlatformInfoV2(u64);
    impl Debug;
    /// Returns the bit state of SMT
    pub smt_enabled, _: 0, 0;
    /// Returns the bit state of TSME.
    pub tsme_enabled, _: 1, 1;
    /// Indicates that the platform is currently using ECC memory
    pub ecc_enabled, _: 2, 2;
    /// Indicates that the RAPL feature is disabled
    pub rapl_disabled, _: 3, 3;
    /// Indicates that ciphertext hiding is enabled
    pub ciphertext_hiding_enabled, _: 4, 4;
    /// Indicates that alias detection has completed since the last system reset and there are no aliasing addresses. Resets to 0.
    pub alias_check_complete, _: 5, 5;
    /// reserved
    reserved, _: 6, 63;
}

impl Display for PlatformInfoV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Platform Info ({}):
  SMT Enabled:               {}
  TSME Enabled:              {}
  ECC Enabled:               {}
  RAPL Disabled:             {}
  Ciphertext Hiding Enabled: {}
  Alias Check Complete:      {}
"#,
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
    #[derive(Default, Deserialize, Clone, Copy, Eq, PartialEq, Serialize)]
    pub struct KeyInfo(u32);
    impl Debug;
    /// AUTHOR_KEY_EN field: Indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST
    pub author_key_en, _: 0;
    /// MASK_CHIP_KEY field: The value of MaskChipKey
    /// (0) Firmware signs the attestation report with either the VCEK OR VLEK.
    /// (1) The firmware writes 0s into the SIGNATURE field instead of signing the report.
    pub mask_chip_key, _: 1,1;
    /// SIGNING_KEY field: Encodes the key used to sign this report.
    /// (0) VCEK
    /// (1) VLEK
    /// (2-6) RESERVED
    /// (7) NONE
    pub signing_key, _: 4,2;
    /// reserved
    reserved, _: 5, 31;
}

impl Display for KeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let signing_key = match self.signing_key() {
            0 => "vcek",
            1 => "vlek",
            7 => "none",
            _ => "unkown",
        };

        write!(
            f,
            r#"
Key Information:
    author key enabled: {}
    mask chip key:      {}
    signing key:        {}
"#,
            self.author_key_en(),
            self.mask_chip_key(),
            signing_key
        )
    }
}
