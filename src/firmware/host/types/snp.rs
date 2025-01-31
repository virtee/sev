// SPDX-License-Identifier: Apache-2.0

/// A representation of the type of data provided to [parse_table](crate::firmware::host::parse_table)
pub use crate::firmware::linux::host::types::RawData;

pub(crate) use crate::firmware::linux::host as FFI;

use crate::Version;

#[cfg(target_os = "linux")]
use crate::error::CertError;

use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Display, Formatter},
};

use bitfield::bitfield;

use bitflags;

use serde::{Deserialize, Serialize};

use self::FFI::types::SnpSetConfig;

bitflags::bitflags! {
    /// The platform's status flags.
    #[derive(Default)]
    pub struct SnpPlatformStatusFlags: u32 {
        /// If set, this platform is owned. Otherwise, it is self-owned.
        const OWNED           = 1 << 0;

        /// If set, encrypted state functionality is present.
        const ENCRYPTED_STATE = 1 << 8;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
/// Certificates which are accepted for [CertTableEntry](self::CertTableEntry)
pub enum CertType {
    /// Empty or closing entry for the CertTable
    Empty,

    /// AMD Root Signing Key (ARK) certificate
    ARK,

    /// AMD SEV Signing Key (ASK) certificate
    ASK,

    /// Versioned Chip Endorsement Key (VCEK) certificate
    VCEK,

    /// Versioned Loaded Endorsement Key (VLEK) certificate
    VLEK,

    /// Certificate Revocation List (CRLs) certificate(s)
    CRL,

    /// Other (Specify GUID)
    OTHER(uuid::Uuid),
}

impl Display for CertType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let guid = match self {
            CertType::Empty => "00000000-0000-0000-0000-000000000000".to_string(),
            CertType::ARK => "c0b406a4-a803-4952-9743-3fb6014cd0ae".to_string(),
            CertType::ASK => "4ab7b379-bbac-4fe4-a02f-05aef327c782".to_string(),
            CertType::VCEK => "63da758d-e664-4564-adc5-f4b93be8accd".to_string(),
            CertType::VLEK => "a8074bc2-a25a-483e-aae6-39c045a0b8a1".to_string(),
            CertType::CRL => "92f81bc3-5811-4d3d-97ff-d19f88dc67ea".to_string(),
            CertType::OTHER(guid) => guid.to_string(),
        };

        write!(f, "{}", guid)
    }
}

impl TryFrom<CertType> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(value: CertType) -> Result<Self, Self::Error> {
        match value {
            CertType::Empty => uuid::Uuid::parse_str(&CertType::Empty.to_string()),
            CertType::ARK => uuid::Uuid::parse_str(&CertType::ARK.to_string()),
            CertType::ASK => uuid::Uuid::parse_str(&CertType::ASK.to_string()),
            CertType::VCEK => uuid::Uuid::parse_str(&CertType::VCEK.to_string()),
            CertType::VLEK => uuid::Uuid::parse_str(&CertType::VLEK.to_string()),
            CertType::CRL => uuid::Uuid::parse_str(&CertType::CRL.to_string()),
            CertType::OTHER(guid) => Ok(guid),
        }
    }
}

impl TryFrom<&uuid::Uuid> for CertType {
    type Error = uuid::Error;

    fn try_from(value: &uuid::Uuid) -> Result<Self, Self::Error> {
        Ok(match value.to_string().as_str() {
            "00000000-0000-0000-0000-000000000000" => CertType::Empty,
            "c0b406a4-a803-4952-9743-3fb6014cd0ae" => CertType::ARK,
            "4ab7b379-bbac-4fe4-a02f-05aef327c782" => CertType::ASK,
            "63da758d-e664-4564-adc5-f4b93be8accd" => CertType::VCEK,
            "a8074bc2-a25a-483e-aae6-39c045a0b8a1" => CertType::VLEK,
            "92f81bc3-5811-4d3d-97ff-d19f88dc67ea" => CertType::CRL,
            _ => CertType::OTHER(*value),
        })
    }
}

impl Ord for CertType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::ARK, Self::ARK)
            | (Self::ASK, Self::ASK)
            | (Self::VCEK, Self::VCEK)
            | (Self::VLEK, Self::VLEK)
            | (Self::CRL, Self::CRL)
            | (Self::Empty, Self::Empty) => std::cmp::Ordering::Equal,
            (Self::OTHER(left), Self::OTHER(right)) => left.cmp(right),
            (Self::Empty, _) => std::cmp::Ordering::Greater,
            (_, Self::Empty) => std::cmp::Ordering::Less,
            (Self::OTHER(_), _) => std::cmp::Ordering::Greater,
            (_, Self::OTHER(_)) => std::cmp::Ordering::Less,
            (Self::CRL, _) => std::cmp::Ordering::Greater,
            (_, Self::CRL) => std::cmp::Ordering::Less,
            (Self::ASK, _) => std::cmp::Ordering::Greater,
            (_, Self::ASK) => std::cmp::Ordering::Less,
            (Self::VLEK, _) => std::cmp::Ordering::Greater,
            (_, Self::VLEK) => std::cmp::Ordering::Less,
            (Self::VCEK, _) => std::cmp::Ordering::Greater,
            (_, Self::VCEK) => std::cmp::Ordering::Less,
        }
    }
}

impl PartialOrd for CertType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
/// An entry with information regarding a specific certificate.
pub struct CertTableEntry {
    /// A Specificy certificate type.
    pub cert_type: CertType,

    /// The raw data of the certificate.
    pub data: Vec<u8>,
}

impl CertTableEntry {
    /// Façade for retreiving the GUID for the Entry.
    pub fn guid_string(&self) -> String {
        self.cert_type.to_string()
    }

    /// Get an immutable reference to the data stored in the entry.
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Generates a certificate from the str GUID and data provided.
    pub fn from_guid(guid: &uuid::Uuid, data: Vec<u8>) -> Result<Self, uuid::Error> {
        let cert_type: CertType = match guid.try_into() {
            Ok(guid) => guid,
            Err(error) => return Err(error),
        };
        Ok(Self { cert_type, data })
    }

    /// Generates a certificate from the CertType and data provided.
    pub fn new(cert_type: CertType, data: Vec<u8>) -> Self {
        Self { cert_type, data }
    }

    /// Builds a Kernel formatted CertTable for sending the certificate content to the PSP.
    #[cfg(target_os = "linux")]
    pub fn cert_table_to_vec_bytes(table: &[Self]) -> Result<Vec<u8>, CertError> {
        FFI::types::CertTableEntry::uapi_to_vec_bytes(table)
    }

    /// Takes in bytes in kernel CertTable format and returns in user API CertTable format.
    #[cfg(target_os = "linux")]
    pub fn vec_bytes_to_cert_table(bytes: &mut [u8]) -> Result<Vec<Self>, CertError> {
        let cert_bytes_ptr: *mut FFI::types::CertTableEntry =
            bytes.as_mut_ptr() as *mut FFI::types::CertTableEntry;

        Ok(unsafe { FFI::types::CertTableEntry::parse_table(cert_bytes_ptr).unwrap() })
    }
}

impl Ord for CertTableEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cert_type.cmp(&other.cert_type)
    }
}

impl PartialOrd for CertTableEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cert_type.cmp(&other.cert_type))
    }
}

/// Information regarding the SEV-SNP platform's TCB version.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TcbStatus {
    /// Installed TCB version.
    pub platform_version: TcbVersion,

    /// Reported TCB version.
    pub reported_version: TcbVersion,
}

/// A description of the SEV-SNP platform's build information.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct Build {
    /// The version information.
    pub version: Version,

    /// The build ID.
    pub build: u32,
}

bitflags::bitflags! {
    /// Various platform initialization configuration data. Byte 0x3 in SEV-SNP's
    /// STRUCT_PLATFORM_STATUS.
    #[derive(Default)]
    pub struct PlatformInit: u8 {
        /// Indicates if RMP is initialized.
        const IS_RMP_INIT           = 1 << 0;
        /// Indicates that alias detection has completed since the last system reset
        /// and there are no aliasing addresses. Resets to 0.
        /// Added in firmware version:
        ///     Milan family: 1.55.22
        ///     Genoa family: 1.55.38
        const ALIAS_CHECK_COMPLETE  = 1 << 1;
        /// Indicates TIO is enabled. Present if SevTio feature bit is set.
        const IS_TIO_EN             = 1 << 3;
    }
}

/// Query the SEV-SNP platform status.
///
/// (Chapter 8.3; Table 38)
#[derive(Default, Debug)]
#[repr(C)]
pub struct SnpPlatformStatus {
    /// The firmware API version (major.minor)
    pub version: Version,

    /// The platform state.
    pub state: u8,

    /// IsRmpInitiailzied
    pub is_rmp_init: PlatformInit,

    /// The platform build ID.
    pub build_id: u32,

    /// MaskChipId
    pub mask_chip_id: u32,

    /// The number of valid guests maintained by the SEV-SNP firmware.
    pub guest_count: u32,

    /// Installed TCB version.
    pub platform_tcb_version: TcbVersion,

    /// Reported TCB version.
    pub reported_tcb_version: TcbVersion,
}

/// Sets the system wide configuration values for SNP.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Config {
    /// The TCB_VERSION to report in guest attestation reports.
    pub reported_tcb: TcbVersion,

    /// Indicates that the CHIP_ID field in the attestation report will always
    /// be zero.
    pub mask_id: MaskId,

    /// Reserved. Must be zero.
    reserved: [u8; 52],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            reported_tcb: Default::default(),
            mask_id: Default::default(),
            reserved: [0; 52],
        }
    }
}

impl Config {
    /// Used to create a new Config
    pub fn new(reported_tcb: TcbVersion, mask_id: MaskId) -> Self {
        Self {
            reported_tcb,
            mask_id,
            reserved: [0; 52],
        }
    }
}

#[cfg(feature = "snp")]
impl TryFrom<Config> for FFI::types::SnpSetConfig {
    type Error = uuid::Error;

    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut snp_config: SnpSetConfig = Default::default();

        snp_config.reported_tcb = value.reported_tcb;
        snp_config.mask_id = value.mask_id;

        Ok(snp_config)
    }
}

#[cfg(feature = "snp")]
impl TryFrom<FFI::types::SnpSetConfig> for Config {
    type Error = uuid::Error;

    fn try_from(value: FFI::types::SnpSetConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            reported_tcb: value.reported_tcb,
            mask_id: value.mask_id,
            ..Default::default()
        })
    }
}

/// TcbVersion represents the version of the firmware.
///
/// (Chapter 2.2; Table 3)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(C)]
pub struct TcbVersion {
    /// Current bootloader version.
    /// SVN of PSP bootloader.
    pub bootloader: u8,
    /// Current PSP OS version.
    /// SVN of PSP operating system.
    pub tee: u8,
    _reserved: [u8; 4],
    /// Version of the SNP firmware.
    /// Security Version Number (SVN) of SNP firmware.
    pub snp: u8,
    /// Lowest current patch level of all the cores.
    pub microcode: u8,
}

impl Display for TcbVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
TCB Version:
  Microcode:   {}
  SNP:         {}
  TEE:         {}
  Boot Loader: {}
  "#,
            self.microcode, self.snp, self.tee, self.bootloader
        )
    }
}

impl TcbVersion {
    /// Creates a new instance of a TcbVersion
    pub fn new(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        Self {
            bootloader,
            tee,
            snp,
            microcode,
            _reserved: Default::default(),
        }
    }
}

bitfield! {
    /// Mask ID values that would go into an SNP CONFIG
    ///
    /// | Bit(s) | Name | Description |
    /// |--------|------|-------------|
    /// |0|MASK_CHIP_ID|Indicates that the CHIP_ID field in the attestation report will alwaysbe zero.|
    /// |1|MASK_CHIP_KEY|Indicates that the VCEK is not used in attestation and guest key derivation.|
    #[repr(C)]
    #[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MaskId(u32);
    impl Debug;
    /// Indicates that the CHIP_ID field in the attestation report will alwaysbe zero.
    pub mask_chip_id, _: 0, 0;
    /// Indicates that the VCEK is not used in attestation and guest key derivation.
    pub mask_chip_key, _: 1, 1;
}

impl Display for MaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
    MaskID ({}):
    Mask Chip ID: {}
    ABI Chip Key: {}"#,
            self.0,
            self.mask_chip_id(),
            self.mask_chip_key(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{CertType, SnpPlatformStatusFlags};
    use uuid::Uuid;

    #[test]
    fn test_cert_type_sort_vcek() {
        let mut certs: Vec<CertType> = vec![
            CertType::Empty,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            CertType::OTHER(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            CertType::ARK,
            CertType::ASK,
            CertType::VCEK,
        ];

        let sorted_certs: Vec<CertType> = vec![
            CertType::ARK,
            CertType::VCEK,
            CertType::ASK,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::OTHER(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            CertType::Empty,
        ];
        certs.sort();
        assert_eq!(certs, sorted_certs);
    }

    #[test]
    fn test_cert_type_sort_vlek() {
        let mut certs: Vec<CertType> = vec![
            CertType::Empty,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::OTHER(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            CertType::ARK,
            CertType::ASK,
            CertType::VLEK,
        ];

        let sorted_certs: Vec<CertType> = vec![
            CertType::ARK,
            CertType::VLEK,
            CertType::ASK,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::OTHER(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            CertType::Empty,
        ];
        certs.sort();
        assert_eq!(certs, sorted_certs);
    }

    #[test]
    fn test_snp_platform_status_flags_zeroed() {
        let actual: SnpPlatformStatusFlags = SnpPlatformStatusFlags { bits: 0 };

        assert_eq!((actual & SnpPlatformStatusFlags::OWNED).bits(), 0);
        assert_eq!((actual & SnpPlatformStatusFlags::ENCRYPTED_STATE).bits(), 0);
    }

    #[test]
    fn test_snp_platform_status_flags_full() {
        let mut actual: SnpPlatformStatusFlags = SnpPlatformStatusFlags { bits: 0 };

        actual |= SnpPlatformStatusFlags::OWNED;
        actual |= SnpPlatformStatusFlags::ENCRYPTED_STATE;

        assert_eq!((actual & SnpPlatformStatusFlags::OWNED).bits(), 1);
        assert_eq!(
            (actual & SnpPlatformStatusFlags::ENCRYPTED_STATE).bits(),
            1 << 8
        );
    }

    #[test]
    fn test_cert_type_fmt() {
        let mut cert_type: CertType = CertType::Empty;
        let mut expected: &str = "00000000-0000-0000-0000-000000000000";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::ARK;
        expected = "c0b406a4-a803-4952-9743-3fb6014cd0ae";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::ASK;
        expected = "4ab7b379-bbac-4fe4-a02f-05aef327c782";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::VCEK;
        expected = "63da758d-e664-4564-adc5-f4b93be8accd";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::VLEK;
        expected = "a8074bc2-a25a-483e-aae6-39c045a0b8a1";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::CRL;
        expected = "92f81bc3-5811-4d3d-97ff-d19f88dc67ea";

        assert_eq!(cert_type.to_string(), expected.to_string());
    }
}
