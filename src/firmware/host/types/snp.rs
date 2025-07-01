// SPDX-License-Identifier: Apache-2.0

use crate::firmware::guest::{parse_tcb, write_tcb};
pub(crate) use crate::firmware::linux::host as FFI;
/// A representation of the type of data provided to [parse_table](crate::firmware::host::parse_table)
pub use crate::firmware::linux::host::types::RawData;

#[cfg(target_os = "linux")]
use crate::error::CertError;
use crate::{
    util::{
        array::Array,
        parser::{ByteParser, ReadExt, WriteExt},
    },
    Generation,
};

use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Display, Formatter},
    io::Write,
    ops::BitOrAssign,
};

use bitfield::bitfield;

use serde::{Deserialize, Serialize};

use self::FFI::types::SnpSetConfig;

bitfield! {
    /// The platform's status flags.
    #[derive(Default)]
    pub struct SnpPlatformStatusFlags(u32);
    impl Debug;

    /// If set, this platform is owned. Otherwise, it is self-owned.
    pub is_owned, _: 0;

    /// If set, encrypted state functionality is present.
    pub is_encrypted_state_present, _: 8;
}

impl BitOrAssign for SnpPlatformStatusFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
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
        Ok(Self {
            cert_type: guid.try_into()?,
            data,
        })
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
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct TcbStatus {
    /// Installed TCB version.
    pub platform_version: TcbVersion,

    /// Reported TCB version.
    pub reported_version: TcbVersion,
}

bitfield! {
    /// Various platform initialization configuration data. Byte 0x3 in SEV-SNP's
    /// STRUCT_PLATFORM_STATUS.
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    pub struct PlatformInit(u8);
    impl Debug;

    /// Indicates if RMP is initialized.
    pub is_rmp_init, _: 0;

    /// Indicates that alias detection has completed since the last system reset
    /// and there are no aliasing addresses. Resets to 0.
    /// Added in firmware version:
    ///     Milan family: 1.55.22
    ///     Genoa family: 1.55.38
    pub alias_check_complete, _: 1;

    /// Indicates TIO is enabled. Present if SevTio feature bit is set.
    pub is_tio_en, _: 3;
}

impl BitOrAssign for PlatformInit {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl ByteParser for PlatformInit {
    type Bytes = [u8; 1];

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self(u8::from_le_bytes(bytes))
    }

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }

    fn default() -> Self {
        Self(Default::default())
    }
}

impl Default for PlatformInit {
    fn default() -> Self {
        Self(ByteParser::default())
    }
}

/// Query the SEV-SNP platform status.
///
/// (Chapter 8.3; Table 38)
#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct SnpPlatformStatus {
    /// The firmware API version (major.minor)
    pub version: (u8, u8),

    /// The platform state.
    pub state: u8,

    /// IsRmpInitiailzied
    pub is_rmp_init: PlatformInit,

    /// The platform build ID.
    pub build_id: u32,

    /// PlatforPolicy of the machine
    pub platform_policy: PlatformPolicy,

    /// The number of valid guests maintained by the SEV-SNP firmware.
    pub guest_count: u32,

    /// Installed TCB version.
    pub platform_tcb_version: TcbVersion,

    /// Reported TCB version.
    pub reported_tcb_version: TcbVersion,
}
#[cfg(feature = "snp")]
impl TryFrom<(Generation, &[u8])> for SnpPlatformStatus {
    type Error = std::io::Error;

    fn try_from(mut value: (Generation, &[u8])) -> Result<Self, Self::Error> {
        //Cast FFI type to rust friendly type
        let stepper: &mut &[u8] = &mut value.1;
        let major: u8 = stepper.parse_bytes()?;
        let minor: u8 = stepper.parse_bytes()?;

        // Find generation from CPUID
        Ok(match value.0 {
            Generation::Turin => Self {
                version: (major, minor),
                state: stepper.parse_bytes()?,
                is_rmp_init: stepper.parse_bytes()?,
                build_id: stepper.parse_bytes()?,
                platform_policy: stepper.parse_bytes()?,
                guest_count: stepper.parse_bytes()?,
                platform_tcb_version: TcbVersion::from_turin_bytes(&stepper.parse_bytes()?),
                reported_tcb_version: TcbVersion::from_turin_bytes(&stepper.parse_bytes()?),
            },
            _ => Self {
                version: (major, minor),
                state: stepper.parse_bytes()?,
                is_rmp_init: stepper.parse_bytes()?,
                build_id: stepper.parse_bytes()?,
                platform_policy: stepper.parse_bytes()?,
                guest_count: stepper.parse_bytes()?,
                platform_tcb_version: TcbVersion::from_legacy_bytes(&stepper.parse_bytes()?),
                reported_tcb_version: TcbVersion::from_legacy_bytes(&stepper.parse_bytes()?),
            },
        })
    }
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
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(C)]
pub struct TcbVersion {
    /// Current FMC fw version
    /// SVN of FMC fw
    pub fmc: Option<u8>,
    /// Current bootloader version.
    /// SVN of PSP bootloader.
    pub bootloader: u8,
    /// Current PSP OS version.
    /// SVN of PSP operating system.
    pub tee: u8,
    /// Version of the SNP firmware.
    /// Security Version Number (SVN) of SNP firmware.
    pub snp: u8,
    /// Lowest current patch level of all the cores.
    pub microcode: u8,
}

impl TcbVersion {
    pub(crate) fn from_legacy_bytes(bytes: &[u8; 8]) -> Self {
        Self {
            fmc: None,
            bootloader: bytes[0],
            tee: bytes[1],
            snp: bytes[6],
            microcode: bytes[7],
        }
    }

    pub(crate) fn to_legacy_bytes(self) -> [u8; 8] {
        [
            self.bootloader,
            self.tee,
            0,
            0,
            0,
            0,
            self.snp,
            self.microcode,
        ]
    }

    pub(crate) fn from_turin_bytes(bytes: &[u8; 8]) -> Self {
        Self {
            fmc: Some(bytes[0]),
            bootloader: bytes[1],
            tee: bytes[2],
            snp: bytes[3],
            microcode: bytes[7],
        }
    }

    pub(crate) fn to_turin_bytes(self) -> [u8; 8] {
        [
            self.fmc.unwrap_or(0),
            self.bootloader,
            self.tee,
            self.snp,
            0,
            0,
            0,
            self.microcode,
        ]
    }
}

impl Display for TcbVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"TCB Version:
  Microcode:   {}
  SNP:         {}
  TEE:         {}
  Boot Loader: {}
  FMC:         {}"#,
            self.microcode,
            self.snp,
            self.tee,
            self.bootloader,
            self.fmc.map_or("None".to_string(), |fmc| fmc.to_string())
        )
    }
}

impl TcbVersion {
    /// Creates a new instance of a TcbVersion
    pub fn new(fmc: Option<u8>, bootloader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        Self {
            fmc,
            bootloader,
            tee,
            snp,
            microcode,
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
    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MaskId(u32);
    impl Debug;
    /// Indicates that the CHIP_ID field in the attestation report will alwaysbe zero.
    pub mask_chip_id, _: 0;
    /// Indicates that the VCEK is not used in attestation and guest key derivation.
    pub mask_chip_key, _: 1;
}

impl Default for MaskId {
    fn default() -> Self {
        Self(ByteParser::default())
    }
}

impl ByteParser for MaskId {
    type Bytes = [u8; 4];

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self(u32::from_le_bytes(bytes))
    }

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }

    fn default() -> Self {
        Self(0)
    }
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

bitfield! {
    /// Policy settings that appear in SNP PLATFORM STATUS
    ///
    /// | Bit(s) | Name | Description |
    /// |--------|------|-------------|
    /// |0|MASK_CHIP_ID|Set to the value of MaskChipID.|
    /// |1|MASK_CHIP_KEY|Set to the value of MaskChipKey.|
    /// |2|VLEK_EN|Indicates whether a VLEK hashtick is loaded|
    /// |3|FEATURE_INFO|Indicates that the SNP_FEATURE_INFO command is available.|
    /// |4|RAPL_DIS|Indicates that the RAPL is disabled.|
    /// |5|CIPHERTEXT_HIDING_DRAM_CAP|Indicates platform capable of ciphertext hiding for the DRAM.|
    /// |6|CIPHERTEXT_HIDING_DRAM_EN|Indicates ciphertext hiding is enabled for the DRAM.|
    /// |31:7|-|Reserved.|
    #[repr(C)]
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PlatformPolicy(u32);
    impl Debug;
    /// Indicates that the CHIP_ID field in the attestation report will alwaysbe zero.
    pub mask_chip_id, _: 0;
    /// Indicates that the VCEK is not used in attestation and guest key derivation.
    pub mask_chip_key, _: 1;
    /// Indicates whether a VLEK hashtick is loaded
    pub vlek_en, _: 2;
    /// Indicates that the SNP_FEATURE_INFO command is available.
    pub feature_info, _: 3;
    /// Indicates that the RAPL is disabled.
    pub rapl_dis, _: 4;
    /// Indicates platform capable of ciphertext hiding for the DRAM.
    pub ciphertext_hiding_dram_cap, _: 5;
    /// Indicates ciphertext hiding is enabled for the DRAM.
    pub ciphertext_hiding_dram_en, _: 6;
    /// Indicates TIO is enbaled. Present if SEV-TIO feature bit is set.
    pub is_tio_en, _: 7;
}

impl Default for PlatformPolicy {
    fn default() -> Self {
        Self(ByteParser::default())
    }
}

impl ByteParser for PlatformPolicy {
    type Bytes = [u8; 4];

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self(u32::from_le_bytes(bytes))
    }

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }

    fn default() -> Self {
        Self(0)
    }
}

impl Display for PlatformPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
    MaskID ({}):
    Mask Chip ID Enabled: {}
    Mask Chip Key Enabled: {}
    Vlek Enabled: {}
    Feature Info Enabled {}
    RAPL Disabled: {}
    Ciphertext Capable: {}
    Ciphertext enabled: {}
    SEV-TIO enabled: {}"#,
            self.0,
            self.mask_chip_id(),
            self.mask_chip_key(),
            self.vlek_en(),
            self.feature_info(),
            self.rapl_dis(),
            self.ciphertext_hiding_dram_cap(),
            self.ciphertext_hiding_dram_en(),
            self.is_tio_en()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Wrapped VLEK Hashstick strucutre.
/// As defined in AMD's SEV-SNP specification chapter 8.30
/// An address to a buffer containing this structure is passed to the snp_vlek_load command.
pub struct WrappedVlekHashstick {
    /// IV used to wrap chip-unique key
    pub iv: [u8; 12], // 96 bits = 12 bytes

    /// VLEK hashstick wrapped with a chip-unique key using AES-256-GCM
    pub vlek_wrapped: Array<u8, 384>,

    /// The TCB version associated with this VLEK hashstick
    pub tcb_version: TcbVersion,

    /// AES-256-GCM authentication tag of the wrapped VLEK hashstick and TCB_VERSION
    pub vlek_auth_tag: [u8; 16],
}

impl WrappedVlekHashstick {
    /// Parses raw bytes into the WrappedVlekHashstick structure.
    pub fn from_bytes(mut bytes: &[u8], generation: Generation) -> Result<Self, std::io::Error> {
        if bytes.len() != 432usize {
            return Err(std::io::ErrorKind::InvalidData)?;
        }

        let stepper = &mut bytes;

        let iv: [u8; 12] = stepper.parse_bytes()?;
        let vlek_wrapped: Array<u8, 384> = stepper.skip_bytes::<4>()?.parse_bytes()?;
        let tcb_version = parse_tcb(stepper, &generation)?;
        let vlek_auth_tag: [u8; 16] = stepper.skip_bytes::<8>()?.parse_bytes()?;

        Ok(Self {
            iv,
            vlek_wrapped,
            tcb_version,
            vlek_auth_tag,
        })
    }

    /// Writes the WrappedVlekHashstick structure to bytes.
    pub fn write_bytes(
        self,
        mut handle: impl Write,
        generation: Generation,
    ) -> Result<(), std::io::Error> {
        handle.write_bytes(self.iv)?;
        handle.skip_bytes::<4>()?.write_bytes(self.vlek_wrapped)?;

        write_tcb(&mut handle, &self.tcb_version, &generation)?;

        handle.skip_bytes::<8>()?.write_bytes(self.vlek_auth_tag)?;

        Ok(())
    }
}

impl Display for WrappedVlekHashstick {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
    Wrapped VLEK Hashstick:
    IV:                      {:?}
    VLEK hashstic Wrapped:   {}
    TCB: 
    {}
    VLEK authentication tag: {:?}"#,
            self.iv, self.vlek_wrapped, self.tcb_version, self.vlek_auth_tag
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
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
        let actual: SnpPlatformStatusFlags = SnpPlatformStatusFlags(0);

        assert!(!actual.is_owned());
        assert!(!actual.is_encrypted_state_present());
    }

    #[test]
    fn test_snp_platform_status_flags_full() {
        let mut actual: SnpPlatformStatusFlags = SnpPlatformStatusFlags(0);

        actual.0 |= 1;
        actual.0 |= 1 << 8;
        assert!(actual.is_owned());
        assert!(actual.is_encrypted_state_present());
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

    #[test]
    fn test_cert_table_entry_creation() {
        let data = vec![1, 2, 3, 4];
        let entry = CertTableEntry::new(CertType::ARK, data.clone());

        assert_eq!(entry.cert_type, CertType::ARK);
        assert_eq!(entry.data(), &data);
        assert_eq!(entry.guid_string(), "c0b406a4-a803-4952-9743-3fb6014cd0ae");
    }

    #[test]
    fn test_cert_table_entry_from_guid() {
        let guid = Uuid::parse_str("c0b406a4-a803-4952-9743-3fb6014cd0ae").unwrap();
        let data = vec![1, 2, 3, 4];
        let entry = CertTableEntry::from_guid(&guid, data.clone()).unwrap();

        assert_eq!(entry.cert_type, CertType::ARK);
        assert_eq!(entry.data(), &data);
    }

    #[test]
    fn test_cert_table_entry_invalid_guid() {
        let guid = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let data = vec![1, 2, 3, 4];
        let entry = CertTableEntry::from_guid(&guid, data.clone()).unwrap();

        assert!(matches!(entry.cert_type, CertType::OTHER(_)));
    }

    #[test]
    fn test_cert_table_entry_empty() {
        let entry = CertTableEntry::new(CertType::Empty, vec![]);

        assert_eq!(entry.cert_type, CertType::Empty);
        assert!(entry.data().is_empty());
        assert_eq!(entry.guid_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn test_cert_table_entry_ordering() {
        let entry1 = CertTableEntry::new(CertType::ARK, vec![1]);
        let entry2 = CertTableEntry::new(CertType::ASK, vec![2]);
        let entry3 = CertTableEntry::new(CertType::Empty, vec![3]);

        assert!(entry1 < entry2);
        assert!(entry2 < entry3);
        assert!(entry1 < entry3);
    }

    #[test]
    fn test_cert_table_entry_data_access() {
        let large_data = vec![0u8; 1024];
        let entry = CertTableEntry::new(CertType::VCEK, large_data.clone());

        assert_eq!(entry.data(), &large_data);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_cert_table_conversion() {
        let entries = vec![
            CertTableEntry::new(CertType::ARK, vec![1, 2, 3]),
            CertTableEntry::new(CertType::ASK, vec![4, 5, 6]),
        ];

        let bytes = CertTableEntry::cert_table_to_vec_bytes(&entries).unwrap();
        let converted = CertTableEntry::vec_bytes_to_cert_table(&mut bytes.clone()).unwrap();

        assert_eq!(entries.len(), converted.len());
        assert_eq!(entries[0].cert_type, converted[0].cert_type);
        assert_eq!(entries[1].cert_type, converted[1].cert_type);
    }

    #[test]
    fn test_cert_type_conversion() {
        let ark_guid = Uuid::parse_str("c0b406a4-a803-4952-9743-3fb6014cd0ae").unwrap();
        let cert_type = CertType::try_from(&ark_guid).unwrap();
        assert_eq!(cert_type, CertType::ARK);

        let uuid = Uuid::try_from(CertType::ARK).unwrap();
        assert_eq!(uuid, ark_guid);
    }

    // Test TcbVersion struct and methods
    #[test]
    fn test_tcb_version() {
        let tcb = TcbVersion::new(None, 1, 2, 3, 4);
        assert_eq!(tcb.bootloader, 1);
        assert_eq!(tcb.tee, 2);
        assert_eq!(tcb.snp, 3);
        assert_eq!(tcb.microcode, 4);

        // Test Display implementation
        let display_output = format!("{}", tcb);
        assert!(display_output.contains("Microcode:   4"));
        assert!(display_output.contains("SNP:         3"));
    }

    // Test Config struct and conversions
    #[test]
    #[cfg(feature = "snp")]
    fn test_config() {
        let tcb = TcbVersion::new(None, 1, 2, 3, 4);
        let mask = MaskId(0x3);
        let config = Config::new(tcb, mask);

        assert_eq!(config.reported_tcb, tcb);
        let config_mask = config.mask_id;
        assert_eq!(config_mask, mask);

        // Test conversion to FFI type
        let snp_config: SnpSetConfig = config.try_into().unwrap();
        assert_eq!(snp_config.reported_tcb, tcb);
        let snp_config_mask = snp_config.mask_id;

        assert_eq!(snp_config_mask, mask);
    }

    // Test PlatformInit flags
    #[test]
    fn test_platform_init() {
        let mut init = PlatformInit(0);

        assert!(!init.is_rmp_init());
        init.0 |= 1;
        assert!(init.is_rmp_init());

        assert!(!init.alias_check_complete());
        init.0 |= 1 << 1;
        assert!(init.alias_check_complete());

        assert!(!init.is_tio_en());
        init.0 |= 1 << 3;
        assert!(init.is_tio_en());
    }

    // Test MaskId bitfield operations
    #[test]
    fn test_mask_id() {
        let mut mask = MaskId(0);
        assert!(!mask.mask_chip_id());

        mask.0 = 0x3;
        assert!(mask.mask_chip_id());
        assert!(mask.mask_chip_key());

        // Test Display implementation
        let display_output = format!("{}", mask);
        assert!(display_output.contains("MaskID (3)"));
    }

    // Test SnpPlatformStatus
    #[test]
    fn test_platform_status() {
        let status = SnpPlatformStatus::default();
        assert_eq!(status.state, 0);
        assert_eq!(status.guest_count, 0);

        let init_status = SnpPlatformStatus {
            is_rmp_init: PlatformInit(1),
            ..Default::default()
        };
        assert!(init_status.is_rmp_init.is_rmp_init());
    }

    #[test]
    fn test_tcb_version_creation_and_display() {
        let tcb = TcbVersion::new(None, 1, 2, 3, 4);
        assert_eq!(tcb.bootloader, 1);
        assert_eq!(tcb.tee, 2);
        assert_eq!(tcb.snp, 3);
        assert_eq!(tcb.microcode, 4);

        let display = format!("{}", tcb);
        assert!(display.contains("Microcode:   4"));
        assert!(display.contains("SNP:         3"));
        assert!(display.contains("TEE:         2"));
        assert!(display.contains("Boot Loader: 1"));
    }

    // MaskId Tests
    #[test]
    fn test_mask_id_operations() {
        let mut mask = MaskId(0);
        assert!(!mask.mask_chip_id());
        assert!(!mask.mask_chip_key());

        mask.0 = 0x3;
        assert!(mask.mask_chip_id());
        assert!(mask.mask_chip_key());

        let display = format!("{}", mask);
        assert!(display.contains("MaskID (3)"));
        assert!(display.contains("Mask Chip ID: true"));
    }

    // Config Tests
    #[test]
    #[cfg(feature = "snp")]
    fn test_config_conversions() {
        let tcb = TcbVersion::new(None, 1, 2, 3, 4);
        let mask = MaskId(0x3);
        let config = Config::new(tcb, mask);

        let ffi_config: SnpSetConfig = config.try_into().unwrap();
        assert_eq!(ffi_config.reported_tcb, tcb);
        let ffi_config_mask = ffi_config.mask_id;
        assert_eq!(ffi_config_mask, mask);

        let converted_config: Config = ffi_config.try_into().unwrap();
        assert_eq!(converted_config.reported_tcb, tcb);
        let converted_config_mask = converted_config.mask_id;
        assert_eq!(converted_config_mask, mask);
    }

    // SnpPlatformStatus Tests
    #[test]
    fn test_platform_status_initialization() {
        let mut status = SnpPlatformStatus::default();
        assert_eq!(status.state, 0);
        assert_eq!(status.guest_count, 0);

        status.is_rmp_init = PlatformInit(1);
        assert!(status.is_rmp_init.is_rmp_init());

        status.platform_tcb_version = TcbVersion::new(None, 1, 2, 3, 4);
        assert_eq!(status.platform_tcb_version.snp, 3);
    }

    #[test]
    fn test_tcb_status() {
        let status = TcbStatus {
            platform_version: TcbVersion::new(None, 1, 2, 3, 4),
            reported_version: TcbVersion::new(None, 5, 6, 7, 8),
        };

        assert_eq!(status.platform_version.bootloader, 1);
        assert_eq!(status.reported_version.bootloader, 5);

        let default_status = TcbStatus::default();
        assert_eq!(default_status.platform_version, Default::default());
    }

    #[test]
    #[cfg(feature = "snp")]
    fn test_config_error_cases() {
        let tcb = TcbVersion::new(None, 255, 255, 255, 255);
        let mask = MaskId(u32::MAX);
        let config = Config::new(tcb, mask);

        let ffi_result: Result<SnpSetConfig, _> = config.try_into();
        assert!(ffi_result.is_ok());

        let default_config = Config::default();
        assert_eq!(default_config.reported_tcb, Default::default());
        let default_config_mask_id = default_config.mask_id;
        assert_eq!(default_config_mask_id, Default::default());
    }

    #[test]
    fn test_version_comparisons() {
        let v1 = TcbVersion::new(None, 1, 2, 3, 4);
        let v2 = TcbVersion::new(None, 1, 2, 3, 5);
        let v3 = TcbVersion::new(None, 1, 2, 3, 4);

        assert!(v1 < v2);
        assert_eq!(v1, v3);
        assert!(v2 > v1);

        assert!(v1.partial_cmp(&v2).unwrap().is_lt());
    }

    #[test]
    fn test_platform_status_boundary() {
        let status = SnpPlatformStatus {
            guest_count: u32::MAX,
            build_id: u32::MAX,
            platform_policy: PlatformPolicy(u32::MAX),
            ..Default::default()
        };

        assert_eq!(status.guest_count, u32::MAX);
        assert_eq!(status.build_id, u32::MAX);
    }

    #[test]
    fn test_mask_id_boundary() {
        let mut mask = MaskId(u32::MAX);
        assert!(mask.mask_chip_id());
        assert!(mask.mask_chip_key());

        mask = MaskId(0);
        assert!(!mask.mask_chip_id());
        assert!(!mask.mask_chip_key());
    }

    #[test]
    fn test_config_reserved() {
        let config = Config::default();
        assert_eq!(config.reserved, [0u8; 52]);
    }

    #[test]
    fn test_platform_status_all_fields() {
        let status: SnpPlatformStatus = SnpPlatformStatus {
            version: (1, 2),
            build_id: 0xDEADBEEF,
            platform_policy: PlatformPolicy(0x7f),
            state: 0xFF,
            ..Default::default()
        };
        assert_eq!(status.version.0, 1);
        assert_eq!(status.version.1, 2);
        assert_eq!(status.build_id, 0xDEADBEEF);
        assert!(status.platform_policy.mask_chip_id());
        assert!(status.platform_policy.mask_chip_key());
        assert!(status.platform_policy.vlek_en());
        assert!(status.platform_policy.feature_info());
        assert!(status.platform_policy.rapl_dis());
        assert!(status.platform_policy.ciphertext_hiding_dram_cap());
        assert!(status.platform_policy.ciphertext_hiding_dram_en());
        assert_eq!(status.state, 0xFF);
    }

    #[test]
    fn test_cert_type_deserialization() {
        let cert_types = vec![
            CertType::Empty,
            CertType::ARK,
            CertType::ASK,
            CertType::VCEK,
            CertType::VLEK,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
        ];

        for cert_type in cert_types {
            let serialized = bincode::serialize(&cert_type).unwrap();
            let deserialized: CertType = bincode::deserialize(&serialized).unwrap();
            assert_eq!(cert_type, deserialized);
        }
    }

    #[test]
    fn test_cert_type_try_from_uuid() {
        // Test all valid UUIDs
        let test_cases = vec![
            ("00000000-0000-0000-0000-000000000000", CertType::Empty),
            ("c0b406a4-a803-4952-9743-3fb6014cd0ae", CertType::ARK),
            ("4ab7b379-bbac-4fe4-a02f-05aef327c782", CertType::ASK),
            ("63da758d-e664-4564-adc5-f4b93be8accd", CertType::VCEK),
            ("a8074bc2-a25a-483e-aae6-39c045a0b8a1", CertType::VLEK),
            ("92f81bc3-5811-4d3d-97ff-d19f88dc67ea", CertType::CRL),
            (
                "11111111-1111-1111-1111-111111111111",
                CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            ),
        ];

        for (uuid_str, expected_type) in test_cases {
            let uuid = Uuid::parse_str(uuid_str).unwrap();
            assert_eq!(CertType::try_from(&uuid).unwrap(), expected_type);
        }
    }

    #[test]
    fn test_cert_type_cmp_complete() {
        let mut cert_types = vec![
            CertType::ARK,
            CertType::VCEK,
            CertType::VLEK,
            CertType::ASK,
            CertType::CRL,
            CertType::Empty,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
        ];

        let expected = vec![
            CertType::ARK,
            CertType::VCEK,
            CertType::VLEK,
            CertType::ASK,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::Empty,
        ];

        cert_types.sort();
        assert_eq!(cert_types, expected);
    }

    #[test]
    fn test_cert_table_entry_deserialization() {
        let entry = CertTableEntry::new(CertType::ARK, vec![1, 2, 3, 4]);

        let serialized = bincode::serialize(&entry).unwrap();
        let deserialized: CertTableEntry = bincode::deserialize(&serialized).unwrap();

        assert_eq!(entry.cert_type, deserialized.cert_type);
        assert_eq!(entry.data, deserialized.data);
    }

    #[test]
    fn test_cert_table_entry_cmp_complete() {
        let entries = vec![
            CertTableEntry::new(CertType::ARK, vec![1]),
            CertTableEntry::new(CertType::VCEK, vec![2]),
            CertTableEntry::new(CertType::Empty, vec![4]),
            CertTableEntry::new(CertType::ASK, vec![3]),
        ];

        let mut sorted = entries.clone();
        sorted.sort();

        assert_eq!(sorted[0].cert_type, CertType::ARK);
        assert_eq!(sorted[1].cert_type, CertType::VCEK);
        assert_eq!(sorted[2].cert_type, CertType::ASK);
        assert_eq!(sorted[3].cert_type, CertType::Empty);
    }

    #[test]
    fn test_tcb_version_deserialization() {
        let tcb = TcbVersion::new(None, 1, 2, 3, 4);

        let serialized = bincode::serialize(&tcb).unwrap();
        let deserialized: TcbVersion = bincode::deserialize(&serialized).unwrap();

        assert_eq!(tcb, deserialized);
    }

    #[test]
    fn test_mask_id_deserialization() {
        let test_cases = vec![
            MaskId(0),        // No bits set
            MaskId(0x1),      // chip_id only
            MaskId(0x2),      // chip_key only
            MaskId(0x3),      // Both bits
            MaskId(u32::MAX), // All bits
        ];

        for mask in test_cases {
            let serialized = bincode::serialize(&mask).unwrap();
            let deserialized: MaskId = bincode::deserialize(&serialized).unwrap();

            assert_eq!(mask.0, deserialized.0);
            assert_eq!(mask.mask_chip_id(), deserialized.mask_chip_id());
            assert_eq!(mask.mask_chip_key(), deserialized.mask_chip_key());
        }
    }
    #[test]
    fn test_cert_table_entry_complete_ordering() {
        let entries = vec![
            CertTableEntry::new(CertType::ARK, vec![1, 2, 3]),
            CertTableEntry::new(CertType::ARK, vec![9, 9, 9]), // Same type, different data
            CertTableEntry::new(CertType::VCEK, vec![1]),
            CertTableEntry::new(CertType::ASK, vec![2]),
            CertTableEntry::new(CertType::CRL, vec![3]),
            CertTableEntry::new(CertType::Empty, vec![]),
            CertTableEntry::new(
                CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
                vec![4],
            ),
            CertTableEntry::new(
                CertType::OTHER(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
                vec![5],
            ),
        ];

        // Test equality
        assert_eq!(entries[0], entries[0]);

        // Test ordering
        assert!(entries[0] < entries[2]); // ARK < VCEK
        assert!(entries[2] < entries[3]); // VCEK < ASK
        assert!(entries[3] < entries[4]); // ASK < CRL
        assert!(entries[4] < entries[6]); // CRL < OTHER
        assert!(entries[6] < entries[7]); // OTHER orders by UUID
        assert!(entries[6] < entries[5]); // OTHER < Empty

        // Test transitivity
        assert!(entries[0] < entries[3]); // ARK < ASK
        assert!(entries[0] < entries[5]); // ARK < Empty

        // Verify reverse comparisons
        assert!(entries[5] > entries[0]); // Empty > ARK
        assert!(entries[4] > entries[3]); // CRL > ASK
    }

    #[test]
    fn test_cert_table_entry_sort_and_compare() {
        let mut entries = vec![
            CertTableEntry::new(CertType::Empty, vec![]),
            CertTableEntry::new(CertType::CRL, vec![1]),
            CertTableEntry::new(
                CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
                vec![2],
            ),
            CertTableEntry::new(
                CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
                vec![3],
            ),
            CertTableEntry::new(CertType::ARK, vec![4]),
            CertTableEntry::new(CertType::ASK, vec![5]),
            CertTableEntry::new(CertType::VCEK, vec![6]),
            CertTableEntry::new(CertType::VLEK, vec![7]),
        ];

        let expected = vec![
            CertTableEntry::new(CertType::ARK, vec![4]),
            CertTableEntry::new(CertType::VCEK, vec![6]),
            CertTableEntry::new(CertType::VLEK, vec![7]),
            CertTableEntry::new(CertType::ASK, vec![5]),
            CertTableEntry::new(CertType::CRL, vec![1]),
            CertTableEntry::new(
                CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
                vec![3],
            ),
            CertTableEntry::new(
                CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
                vec![2],
            ),
            CertTableEntry::new(CertType::Empty, vec![]),
        ];

        entries.sort();
        assert_eq!(entries, expected);

        // Verify stability with duplicate types
        let mut duplicates = [
            CertTableEntry::new(CertType::ARK, vec![1]),
            CertTableEntry::new(CertType::ARK, vec![2]),
        ];
        duplicates.sort();
        assert_eq!(duplicates[0].data(), &[1]);
        assert_eq!(duplicates[1].data(), &[2]);
    }

    #[test]
    fn test_cert_table_entry_direct_cmp() {
        let entry1 = CertTableEntry::new(CertType::ARK, vec![1]);
        let entry2 = CertTableEntry::new(CertType::VCEK, vec![2]);

        // Direct call to cmp() method to ensure coverage
        let ordering = entry1.cmp(&entry2);
        assert!(matches!(ordering, std::cmp::Ordering::Less));

        // Reverse comparison
        let ordering = entry2.cmp(&entry1);
        assert!(matches!(ordering, std::cmp::Ordering::Greater));

        // Equal comparison
        let ordering = entry1.cmp(&entry1);
        assert!(matches!(ordering, std::cmp::Ordering::Equal));
    }

    #[test]
    fn test_cert_table_entry_direct_cmp_vlek() {
        let entry1 = CertTableEntry::new(CertType::ARK, vec![1]);
        let entry2 = CertTableEntry::new(CertType::VLEK, vec![2]);

        // Direct call to cmp() method to ensure coverage
        let ordering = entry1.cmp(&entry2);
        assert!(matches!(ordering, std::cmp::Ordering::Less));

        // Reverse comparison
        let ordering = entry2.cmp(&entry1);
        assert!(matches!(ordering, std::cmp::Ordering::Greater));

        // Equal comparison
        let ordering = entry1.cmp(&entry1);
        assert!(matches!(ordering, std::cmp::Ordering::Equal));
    }
    #[test]
    fn test_cert_table_entry_deserialize() {
        use bincode::{deserialize, serialize};

        // Create a test entry
        let original = CertTableEntry::new(CertType::ARK, vec![0x41, 0x42, 0x43]);

        // Serialize and then deserialize
        let serialized = serialize(&original).expect("Failed to serialize");
        let deserialized: CertTableEntry = deserialize(&serialized).expect("Failed to deserialize");

        // Verify deserialized data matches original
        assert_eq!(deserialized.cert_type, original.cert_type);
        assert_eq!(deserialized.data(), original.data());
    }

    #[test]
    fn test_cert_type_to_uuid_conversion() {
        use uuid::Uuid;

        // Test successful conversions
        assert_eq!(
            Uuid::try_from(CertType::ARK).unwrap(),
            Uuid::parse_str("c0b406a4-a803-4952-9743-3fb6014cd0ae").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::ASK).unwrap(),
            Uuid::parse_str("4ab7b379-bbac-4fe4-a02f-05aef327c782").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::VCEK).unwrap(),
            Uuid::parse_str("63da758d-e664-4564-adc5-f4b93be8accd").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::VLEK).unwrap(),
            Uuid::parse_str("a8074bc2-a25a-483e-aae6-39c045a0b8a1").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::Empty).unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::CRL).unwrap(),
            Uuid::parse_str("92f81bc3-5811-4d3d-97ff-d19f88dc67ea").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::OTHER(uuid::Uuid::max())).unwrap(),
            Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap()
        );
    }

    #[test]
    fn test_chain_visitor_methods() {
        use bincode::{deserialize, serialize};
        // Test sequence visiting
        let chain_data = vec![
            CertTableEntry::new(CertType::ARK, vec![1]),
            CertTableEntry::new(CertType::ASK, vec![2]),
        ];
        let serialized = serialize(&chain_data).expect("Failed to serialize");
        let deserialized: Vec<CertTableEntry> =
            deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), chain_data.len());
        assert_eq!(deserialized[0].cert_type, chain_data[0].cert_type);
    }

    #[test]
    fn test_field_visitor_methods() {
        use bincode::{deserialize, serialize};

        // Test various field types
        let bytes = vec![1u8, 2u8, 3u8];
        let serialized = serialize(&bytes).expect("Failed to serialize");
        let deserialized: Vec<u8> = deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(deserialized, bytes);

        // Test string field
        let text = "test";
        let serialized = serialize(&text).expect("Failed to serialize");
        let deserialized: String = deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(deserialized, text);
    }

    #[test]
    fn test_snp_platform_status_flags_bitor_assign() {
        let mut flags1 = SnpPlatformStatusFlags::default();
        let flags2 = SnpPlatformStatusFlags::default();
        flags1 |= flags2;
        assert_eq!(flags1.0, 0);

        let mut flags1 = SnpPlatformStatusFlags(1);
        let flags2 = SnpPlatformStatusFlags(2);
        flags1 |= flags2;
        assert_eq!(flags1.0, 3);
    }

    #[test]
    fn test_platform_init_bitor_assign() {
        let mut init1: PlatformInit = Default::default();
        let init2: PlatformInit = Default::default();
        init1 |= init2;
        assert_eq!(init1.0, 0);

        let mut init1 = PlatformInit(1);
        let init2 = PlatformInit(2);
        init1 |= init2;
        assert_eq!(init1.0, 3);
    }

    #[test]
    fn test_tcb_version_default() {
        let tcb_version: TcbVersion = Default::default();
        assert_eq!(tcb_version.bootloader, 0);
        assert_eq!(tcb_version.tee, 0);
        assert_eq!(tcb_version.snp, 0);
        assert_eq!(tcb_version.microcode, 0);
    }

    #[test]
    fn test_mask_id_from_bytes() {
        let bytes: [u8; 4] = [0b11, 0b11, 0b11, 0b11];
        let mask_id = MaskId::from_bytes(bytes);
        assert!(mask_id.mask_chip_id());
        assert!(mask_id.mask_chip_key());
    }

    #[test]
    fn test_mask_id_to_bytes() {
        let mask_id = MaskId(0x01020304);
        let bytes = mask_id.to_bytes();
        assert_eq!(bytes, [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_mask_id_default() {
        let mask_id: MaskId = Default::default();
        assert_eq!(mask_id.0, 0);
    }

    #[test]
    fn test_snp_platform_status_non_turin() {
        let expected: SnpPlatformStatus = SnpPlatformStatus {
            version: (1, 1),
            state: 1,
            is_rmp_init: PlatformInit(1),
            build_id: 1,
            platform_policy: PlatformPolicy(1),
            guest_count: 0,
            platform_tcb_version: TcbVersion {
                fmc: None,
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
            reported_tcb_version: TcbVersion {
                fmc: None,
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
        };
        let raw_actual: FFI::types::SnpPlatformStatus = FFI::types::SnpPlatformStatus {
            buffer: [
                1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, // Other stuff
                1, 1, 0, 0, 0, 0, 1, 1, //Platform TCB
                1, 1, 0, 0, 0, 0, 1, 1, //Reported TCB
            ],
        };
        let actual: SnpPlatformStatus = (Generation::Milan, &*raw_actual).try_into().unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_snp_platform_status_turin() {
        let expected: SnpPlatformStatus = SnpPlatformStatus {
            version: (1, 1),
            state: 1,
            is_rmp_init: PlatformInit(1),
            build_id: 1,
            platform_policy: PlatformPolicy(1),
            guest_count: 0,
            platform_tcb_version: TcbVersion {
                fmc: Some(1),
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
            reported_tcb_version: TcbVersion {
                fmc: Some(1),
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
        };
        let raw_actual: FFI::types::SnpPlatformStatus = FFI::types::SnpPlatformStatus {
            buffer: [
                1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, // Other stuff
                1, 1, 1, 1, 0, 0, 0, 1, //Platform TCB
                1, 1, 1, 1, 0, 0, 0, 1, //Reported TCB
            ],
        };
        let actual: SnpPlatformStatus = (Generation::Turin, &*raw_actual).try_into().unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_wrapped_vlek_hashstick_from_bytes() {
        // Create a test buffer with the correct layout
        let mut test_buffer = Vec::with_capacity(432);

        // IV (12 bytes)
        test_buffer.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        // Reserved field 1 (4 bytes of zeros)
        test_buffer.extend_from_slice(&[0, 0, 0, 0]);

        // VLEK_WRAPPED (384 bytes)
        test_buffer.extend_from_slice(&[42; 384]);

        // TCB_VERSION (8 bytes)
        test_buffer.extend_from_slice(&[1, 2, 0, 0, 0, 0, 3, 4]); // bootloader=1, tee=2, snp=3, microcode=4

        // Reserved field 2 (8 bytes of zeros)
        test_buffer.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

        // VLEK_AUTH_TAG (16 bytes)
        test_buffer.extend_from_slice(&[9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0]);

        // Parse the buffer
        let hashstick = WrappedVlekHashstick::from_bytes(&test_buffer, Generation::Milan).unwrap();

        // Verify the fields
        assert_eq!(hashstick.iv, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(hashstick.vlek_wrapped.as_ref(), &[42; 384]);
        assert_eq!(hashstick.tcb_version.bootloader, 1);
        assert_eq!(hashstick.tcb_version.tee, 2);
        assert_eq!(hashstick.tcb_version.snp, 3);
        assert_eq!(hashstick.tcb_version.microcode, 4);
        assert_eq!(
            hashstick.vlek_auth_tag,
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_wrapped_vlek_hashstick_invalid_length() {
        // Test with a buffer that's too short
        let test_buffer = [0u8; 431]; // One byte too short
        let result = WrappedVlekHashstick::from_bytes(&test_buffer, Generation::Milan);
        assert!(result.is_err());

        // Test with a buffer that's too long
        let test_buffer = [0u8; 433]; // One byte too long
        let result = WrappedVlekHashstick::from_bytes(&test_buffer, Generation::Milan);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrapped_vlek_hashstick_write_bytes() {
        // Create a test hashstick
        let hashstick = WrappedVlekHashstick {
            iv: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vlek_wrapped: Array([42; 384]),
            tcb_version: TcbVersion::new(None, 1, 2, 3, 4),
            vlek_auth_tag: [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0],
        };

        // Write it to a buffer
        let mut buffer = Vec::with_capacity(432);

        hashstick
            .write_bytes(&mut buffer, Generation::Milan)
            .unwrap();

        // Verify the buffer is the correct length
        assert_eq!(buffer.len(), 432);

        // Verify the fields were written correctly
        assert_eq!(&buffer[0..12], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]); // IV
        assert_eq!(&buffer[0x0C..0x10], &[0, 0, 0, 0]); // Reserved field 1
        assert_eq!(&buffer[0x10..0x190], &[42; 384]); // VLEK_WRAPPED

        // TCB_VERSION format depends on the CPU generation, so we'll read it back
        let tcb_bytes = &buffer[0x190..0x198];

        let tcb = TcbVersion::from_legacy_bytes(&tcb_bytes.try_into().unwrap());
        assert_eq!(tcb.bootloader, 1);
        assert_eq!(tcb.tee, 2);
        assert_eq!(tcb.snp, 3);
        assert_eq!(tcb.microcode, 4);

        assert_eq!(&buffer[0x198..0x1A0], &[0, 0, 0, 0, 0, 0, 0, 0]); // Reserved field 2
        assert_eq!(
            &buffer[0x1A0..0x1B0],
            &[9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0]
        ); // VLEK_AUTH_TAG
    }

    #[test]
    fn test_wrapped_vlek_hashstick_display() {
        // Create a test hashstick
        let hashstick = WrappedVlekHashstick {
            iv: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vlek_wrapped: Array([42; 384]),
            tcb_version: TcbVersion::new(None, 1, 2, 3, 4),
            vlek_auth_tag: [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0],
        };

        // Convert to string and check contents
        let display_string = format!("{}", hashstick);
        assert!(display_string.contains("Wrapped VLEK Hashstick:"));
        assert!(display_string.contains("IV:"));
        assert!(display_string.contains("VLEK hashstic Wrapped:"));
        assert!(display_string.contains("TCB:"));
        assert!(display_string.contains("VLEK authentication tag:"));
    }
}
