// SPDX-License-Identifier: Apache-2.0

/// A representation of the type of data provided to [`parse_table`](crate::firmware::host::parse_table)
pub use crate::firmware::linux::host::types::RawData;

pub(crate) use crate::firmware::linux::{host as FFI, _4K_PAGE};

use crate::Version;

use std::convert::{TryFrom, TryInto};

use bitflags;

use serde::{Deserialize, Serialize};

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
/// Certificates which are accepted for [`CertTableEntry`](self::CertTableEntry)
pub enum CertType {
    /// AMD Root Signing Key (ARK) certificate
    ARK,

    /// AMD SEV Signing Key (ASK) certificate
    ASK,

    /// Versioned Chip Endorsement Key (VCEK) certificate
    VCEK,

    /// Other (Specify GUID)
    OTHER(uuid::Uuid),

    /// Empty or closing entry for the CertTable
    Empty,
}

impl ToString for CertType {
    fn to_string(&self) -> String {
        match self {
            CertType::ARK => "c0b406a4-a803-4952-9743-3fb6014cd0ae".to_string(),
            CertType::ASK => "4ab7b379-bbac-4fe4-a02f-05aef327c782".to_string(),
            CertType::VCEK => "63da758d-e664-4564-adc5-f4b93be8accd".to_string(),
            CertType::Empty => "00000000-0000-0000-0000-000000000000".to_string(),
            CertType::OTHER(guid) => guid.to_string(),
        }
    }
}

impl TryFrom<CertType> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(value: CertType) -> Result<Self, Self::Error> {
        match value {
            CertType::ARK => uuid::Uuid::parse_str(&CertType::ARK.to_string()),
            CertType::ASK => uuid::Uuid::parse_str(&CertType::ASK.to_string()),
            CertType::VCEK => uuid::Uuid::parse_str(&CertType::VCEK.to_string()),
            CertType::Empty => uuid::Uuid::parse_str(&CertType::Empty.to_string()),
            CertType::OTHER(guid) => Ok(guid),
        }
    }
}

impl TryFrom<&uuid::Uuid> for CertType {
    type Error = uuid::Error;

    fn try_from(value: &uuid::Uuid) -> Result<Self, Self::Error> {
        Ok(match value.to_string().as_str() {
            "c0b406a4-a803-4952-9743-3fb6014cd0ae" => CertType::ARK,
            "4ab7b379-bbac-4fe4-a02f-05aef327c782" => CertType::ASK,
            "63da758d-e664-4564-adc5-f4b93be8accd" => CertType::VCEK,
            "00000000-0000-0000-0000-000000000000" => CertType::Empty,
            _ => CertType::OTHER(*value),
        })
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
    pub is_rmp_init: u8,

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

/// Rust-friendly instance of the SNP Extended Configuration.
/// It may be used either to fetch or set the configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtConfig {
    /// SET:
    ///     Address of the Config or 0 when reported_tcb does not need
    ///     to be updated.
    ///
    /// GET:
    ///     Address of the Config or 0 when reported_tcb should not be
    ///     fetched.
    pub config: Option<Config>,

    /// SET:
    ///     Address of extended guest request certificate chain or None when
    ///     previous certificate should be removed on SNP_SET_EXT_CONFIG.
    ///
    /// GET:
    ///     Address of extended guest request certificate chain or None when
    ///     certificate should not be fetched.
    pub certs: Option<Vec<CertTableEntry>>,

    /// SET:
    ///     Length of the certificates.
    ///
    /// GET:
    ///     Length of the buffer which will hold the fetched certificates.
    pub certs_len: u32,
}

/// Used to round certificate buffers to 4K page alignment.
fn round_to_whole_pages(size: usize) -> usize {
    match size % _4K_PAGE {
        0 => size,
        rem => size + (_4K_PAGE - rem),
    }
}

impl ExtConfig {
    /// Used to only update the AMD Secure Processor certificates with the certificates provided.
    pub fn new_certs_only(certificates: Vec<CertTableEntry>) -> Self {
        let certs_length: usize = certificates.iter().map(|entry| entry.data().len()).sum();
        let certs_len: u32 = round_to_whole_pages(certs_length) as u32;

        Self {
            config: None,
            certs: Some(certificates),
            certs_len,
        }
    }

    /// Used to only update the AMD Secure Processor configuration with the configuration provided.
    pub fn new_config_only(config: Config) -> Self {
        Self {
            config: Some(config),
            certs: None,
            certs_len: 0,
        }
    }

    /// Creates a new instance of an ExtConfig.
    pub fn new(config: Config, certificates: Vec<CertTableEntry>) -> Self {
        let certs_length: usize = certificates.iter().map(|entry| entry.data().len()).sum();
        let certs_len: u32 = round_to_whole_pages(certs_length) as u32;

        Self {
            config: Some(config),
            certs: Some(certificates),
            certs_len,
        }
    }
}

impl TryFrom<ExtConfig> for FFI::types::SnpGetExtConfig {
    type Error = uuid::Error;

    fn try_from(value: ExtConfig) -> Result<Self, Self::Error> {
        let mut config_address: u64 = 0u64;
        let mut certs_address: u64 = 0u64;
        let certs_len: u32 = value.certs_len;

        if let Some(config) = value.config {
            config_address = &config as *const Config as u64;
        }

        if let Some(certs) = value.certs {
            certs_address = certs.as_ptr() as u64;
        }

        Ok(Self {
            config_address,
            certs_address,
            certs_len,
        })
    }
}

impl TryFrom<ExtConfig> for FFI::types::SnpSetExtConfig {
    type Error = uuid::Error;

    fn try_from(value: ExtConfig) -> Result<Self, Self::Error> {
        let mut config_address: u64 = 0u64;
        let mut certs_address: u64 = 0u64;
        let certs_len: u32 = value.certs_len;

        if let Some(config) = value.config {
            config_address = &config as *const Config as u64;
        }

        if let Some(certs) = value.certs {
            certs_address = certs.as_ptr() as u64;
        }

        Ok(Self {
            config_address,
            certs_address,
            certs_len,
        })
    }
}

impl TryFrom<FFI::types::SnpGetExtConfig> for ExtConfig {
    type Error = uuid::Error;

    fn try_from(value: FFI::types::SnpGetExtConfig) -> Result<Self, Self::Error> {
        let mut config: Option<Config> = None;
        let mut certs: Option<Vec<CertTableEntry>> = None;
        if let Some(config_ref) = unsafe { (value.config_address as *mut Config).as_mut() } {
            config = Some(*config_ref);
        }

        if let Some(certificates) =
            unsafe { (value.certs_address as *mut FFI::types::CertTableEntry).as_mut() }
        {
            certs = Some(unsafe { FFI::types::CertTableEntry::parse_table(certificates)? })
        }

        Ok(Self {
            config,
            certs,
            certs_len: value.certs_len,
        })
    }
}

impl TryFrom<FFI::types::SnpSetExtConfig> for ExtConfig {
    type Error = uuid::Error;

    fn try_from(value: FFI::types::SnpSetExtConfig) -> Result<Self, Self::Error> {
        let mut config: Option<Config> = None;
        let mut certs: Option<Vec<CertTableEntry>> = None;
        if let Some(config_ref) = unsafe { (value.config_address as *mut Config).as_mut() } {
            config = Some(*config_ref);
        }

        if let Some(certificates) =
            unsafe { (value.certs_address as *mut FFI::types::CertTableEntry).as_mut() }
        {
            certs = Some(unsafe { FFI::types::CertTableEntry::parse_table(certificates)? })
        }

        Ok(Self {
            config,
            certs,
            certs_len: value.certs_len,
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
    pub mask_chip_id: u32,

    /// Reserved. Must be zero.
    reserved: [u8; 52],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            reported_tcb: Default::default(),
            mask_chip_id: Default::default(),
            reserved: [0; 52],
        }
    }
}

impl Config {
    /// Used to create a new Config
    pub fn new(reported_tcb: TcbVersion, mask_chip_id: u32) -> Self {
        Self {
            reported_tcb,
            mask_chip_id,
            reserved: [0; 52],
        }
    }
}

/// TcbVersion represents the version of the firmware.
///
/// (Chapter 2.2; Table 3)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

impl From<FFI::types::TcbVersion> for TcbVersion {
    fn from(value: FFI::types::TcbVersion) -> Self {
        Self {
            bootloader: value.bootloader,
            tee: value.tee,
            _reserved: value.reserved,
            snp: value.snp,
            microcode: value.microcode,
        }
    }
}
