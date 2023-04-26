// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

#[cfg(target_os = "linux")]
use super::*;
use std::fmt::Debug;

#[cfg(target_os = "linux")]
pub use super::Firmware;
use crate::firmware::linux::guest::types::_4K_PAGE;
pub use crate::firmware::linux::host::types::{PlatformStatusFlags, SnpConfig, TcbVersion};

use serde::{Deserialize, Serialize};

/// The platform state.
///
/// The underlying SEV platform behaves like a state machine and can
/// only perform certain actions while it is in certain states.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// The platform is uninitialized.
    Uninitialized,

    /// The platform is initialized, but not currently managing any
    /// guests.
    Initialized,

    /// The platform is initialized and is overseeing execution
    /// of encrypted guests.
    Working,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            State::Uninitialized => "uninitialized",
            State::Initialized => "initialized",
            State::Working => "working",
        };
        write!(f, "{state}")
    }
}

/// Information regarding the SEV platform's current status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The build number.
    pub build: Build,

    /// The platform's current state.
    pub state: State,

    /// Additional platform information is encoded into flags.
    ///
    /// These could describe whether encrypted state functionality
    /// is enabled, or whether the platform is self-owned.
    pub flags: PlatformStatusFlags,

    /// The number of valid guests supervised by this platform.
    pub guests: u32,
}

/// The CPU-unique identifier for the platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub Vec<u8>);

impl From<Identifier> for Vec<u8> {
    fn from(id: Identifier) -> Vec<u8> {
        id.0
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{b:02X}")?;
        }

        Ok(())
    }
}

/// Information regarding the SEV-SNP platform's TCB version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpTcbStatus {
    /// Installed TCB version.
    pub platform_version: TcbVersion,

    /// Reported TCB version.
    pub reported_version: TcbVersion,
}

/// Information regarding the SEV-SNP platform's current status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpStatus {
    /// The build number.
    pub build: SnpBuild,

    /// The platform's current state.
    pub state: State,

    /// IsRmpInitiailzied
    pub is_rmp_init: bool,

    /// MaskChipId
    pub mask_chip_id: bool,

    /// The number of valid guests supervised by this platform.
    pub guests: u32,

    /// TCB status.
    pub tcb: SnpTcbStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
/// Certificates which are accepted for [`CertTableEntry`]
pub enum SnpCertType {
    /// AMD Root Signing Key (ARK) certificate
    ARK,

    /// AMD SEV Signing Key (ASK) certificate
    ASK,

    /// Versioned Chip Endorsement Key (VCEK) certificate
    VCEK,

    /// Other (Specify GUID)
    OTHER(String),

    /// Empty or closing entry for the CertTable
    Empty,
}

impl SnpCertType {
    /// Create a certificate from the specified GUID. Any unexpected matches
    /// produce an [`SnpCertType::OTHER`] type from the guid provided.
    fn from_guid(guid: &str) -> Self {
        match guid {
            "c0b406a4-a803-4952-9743-3fb6014cd0ae" => SnpCertType::ARK,
            "4ab7b379-bbac-4fe4-a02f-05aef327c782" => SnpCertType::ASK,
            "63da758d-e664-4564-adc5-f4b93be8accd" => SnpCertType::VCEK,
            "00000000-0000-0000-0000-000000000000" => SnpCertType::Empty,
            guid => SnpCertType::OTHER(guid.to_string()),
        }
    }

    /// Retreive the GUID from the [`SnpCertType`].
    fn guid(&self) -> String {
        match self {
            SnpCertType::ARK => "c0b406a4-a803-4952-9743-3fb6014cd0ae",
            SnpCertType::ASK => "4ab7b379-bbac-4fe4-a02f-05aef327c782",
            SnpCertType::VCEK => "63da758d-e664-4564-adc5-f4b93be8accd",
            SnpCertType::Empty => "00000000-0000-0000-0000-000000000000",
            SnpCertType::OTHER(guid) => guid,
        }
        .to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
/// An entry with information regarding a specific certificate.
pub struct CertTableEntry {
    /// A Specificy certificate type.
    pub cert_type: SnpCertType,

    /// The raw data of the certificate.
    pub data: Vec<u8>,
}

impl CertTableEntry {
    /// Façade for retreiving the GUID for the Entry.
    pub fn guid(&self) -> String {
        self.cert_type.guid()
    }

    /// Get an immutable reference to the data stored in the entry.
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Generates a certificate from the str GUID and data provided.
    pub fn from_guid(guid: &str, data: Vec<u8>) -> Self {
        Self {
            cert_type: SnpCertType::from_guid(guid),
            data,
        }
    }

    /// Generates a certificate from the SnpCertType and data provided.
    pub fn new(cert_type: SnpCertType, data: Vec<u8>) -> Self {
        Self { cert_type, data }
    }
}

/// Rust-friendly instance of the SNP Extended Configuration.
/// It may be used either to fetch or set the configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnpExtConfig {
    /// SET:
    ///     Address of the SnpConfig or 0 when reported_tcb does not need
    ///     to be updated.
    ///
    /// GET:
    ///     Address of the SnpConfig or 0 when reported_tcb should not be
    ///     fetched.
    pub config: Option<SnpConfig>,

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

impl SnpExtConfig {
    /// Used to update the PSP with the cerificates provided.
    pub fn update_certs_only(certificates: Vec<CertTableEntry>) -> Result<Self, SnpCertError> {
        let certs_length: usize = certificates.iter().map(|entry| entry.data().len()).sum();
        let certs_len: u32 = round_to_whole_pages(certs_length) as u32;

        Ok(Self {
            config: None,
            certs: Some(certificates),
            certs_len,
        })
    }
}

#[cfg(test)]
mod test {

    use super::{CertTableEntry, SnpCertType, SnpConfig, SnpExtConfig};
    use crate::firmware::linux::host::types::TcbVersion;

    fn build_ext_config() -> SnpExtConfig {
        let test_cfg: SnpConfig = SnpConfig::new(TcbVersion::new(2, 0, 6, 39), 31);

        let cert_table: Vec<CertTableEntry> =
            vec![CertTableEntry::new(SnpCertType::ARK, vec![1; 28])];

        SnpExtConfig {
            config: Some(test_cfg),
            certs: Some(cert_table),
            certs_len: 4096,
        }
    }

    #[test]
    fn snp_ext_config_get_config() {
        let expected_data: SnpConfig = SnpConfig::new(TcbVersion::new(2, 0, 6, 39), 31);
        let cfg: SnpExtConfig = build_ext_config();
        assert_eq!(cfg.config, Some(expected_data));
    }

    #[test]
    fn snp_ext_config_get_certs() {
        let cert_table: Vec<CertTableEntry> =
            vec![CertTableEntry::new(SnpCertType::ARK, vec![1; 28])];

        let cfg: SnpExtConfig = build_ext_config();
        assert_eq!(cfg.certs, Some(cert_table));
    }
}
