// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

#[cfg(target_os = "linux")]
use super::*;
use std::fmt::Debug;
use std::{error, io};

#[cfg(target_os = "linux")]
pub use super::Firmware;
use crate::firmware::linux::guest::types::_4K_PAGE;
pub use crate::firmware::linux::host::types::{PlatformStatusFlags, SnpConfig, TcbVersion};

use serde::{Deserialize, Serialize};

/// There are a number of error conditions that can occur between this
/// layer all the way down to the SEV platform. Most of these cases have
/// been enumerated; however, there is a possibility that some error
/// conditions are not encapsulated here.
#[derive(Debug)]
pub enum Indeterminate<T: Debug> {
    /// The error condition is known.
    Known(T),

    /// The error condition is unknown.
    Unknown,
}

#[derive(Debug)]
/// Wrapper Error for Firmware or User API Errors
pub enum UserApiError {
    /// Firmware related errors.
    FirmwareError(Error),

    /// User API related errors.
    ApiError(SnpCertError),
}

impl error::Error for UserApiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            UserApiError::ApiError(uapi_error) => Some(uapi_error),
            UserApiError::FirmwareError(firmware_error) => Some(firmware_error),
        }
    }
}

impl std::fmt::Display for UserApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let err_msg: String = match self {
            UserApiError::FirmwareError(error) => format!("Firmware Error Encountered: {error}"),
            UserApiError::ApiError(error) => format!("Certificate Error Encountered: {error}"),
        };
        write!(f, "{err_msg}")
    }
}

impl std::convert::From<Error> for UserApiError {
    fn from(firmware_error: Error) -> Self {
        UserApiError::FirmwareError(firmware_error)
    }
}

impl std::convert::From<std::io::Error> for UserApiError {
    fn from(io_error: std::io::Error) -> Self {
        UserApiError::FirmwareError(Error::IoError(io_error))
    }
}

impl std::convert::From<SnpCertError> for UserApiError {
    fn from(cert_error: SnpCertError) -> Self {
        UserApiError::ApiError(cert_error)
    }
}

#[derive(Debug)]
/// Errors which may be encountered through misuse of the User API.
pub enum SnpCertError {
    /// Malformed GUID.
    InvalidGUID,

    /// Malformed Page Allignment
    PageMisallignment,

    /// Unknown Error.
    UnknownError,
}

impl std::fmt::Display for SnpCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SnpCertError::InvalidGUID => write!(f, "Invalid GUID provided in certificate chain."),
            SnpCertError::PageMisallignment => {
                write!(f, "Certificate Buffer not alligned with 4K Pages.")
            }
            SnpCertError::UnknownError => {
                write!(f, "Unknown Error encountered within the certificate chain.")
            }
        }
    }
}

impl error::Error for SnpCertError {}

/// Error conditions returned by the SEV platform or by layers above it
/// (i.e., the Linux kernel).
///
/// These error conditions are documented in the AMD SEV API spec, but
/// their documentation has been copied here for completeness.
#[derive(Debug)]
pub enum Error {
    /// Something went wrong when communicating with the "outside world"
    /// (kernel, SEV platform).
    IoError(io::Error),

    /// The platform state is invalid for this command.
    InvalidPlatformState,

    /// The guest state is invalid for this command.
    InvalidGuestState,

    /// The platform configuration is invalid.
    InvalidConfig,

    /// A memory buffer is too small.
    InvalidLen,

    /// The platform is already owned.
    AlreadyOwned,

    /// The certificate is invalid.
    InvalidCertificate,

    /// Request is not allowed by guest policy.
    PolicyFailure,

    /// The guest is inactive.
    Inactive,

    /// The address provided is invalid.
    InvalidAddress,

    /// The provided signature is invalid.
    BadSignature,

    /// The provided measurement is invalid.
    BadMeasurement,

    /// The ASID is already owned.
    AsidOwned,

    /// The ASID is invalid.
    InvalidAsid,

    /// WBINVD instruction required.
    WbinvdRequired,

    /// `DF_FLUSH` invocation required.
    DfFlushRequired,

    /// The guest handle is invalid.
    InvalidGuest,

    /// The command issued is invalid.
    InvalidCommand,

    /// The guest is active.
    Active,

    /// A hardware condition has occurred affecting the platform. It is safe
    /// to re-allocate parameter buffers.
    HardwarePlatform,

    /// A hardware condition has occurred affecting the platform. Re-allocating
    /// parameter buffers is not safe.
    HardwareUnsafe,

    /// Feature is unsupported.
    Unsupported,

    /// A given parameter is invalid.
    InvalidParam,

    /// The SEV firmware has run out of a resource required to carry out the
    /// command.
    ResourceLimit,

    /// The SEV platform observed a failed integrity check.
    SecureDataInvalid,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_description = match self {
            Error::IoError(_) => "I/O Error",
            Error::InvalidPlatformState => "Invalid platform state",
            Error::InvalidGuestState => "Invalid guest state",
            Error::InvalidConfig => "Platform configuration invalid",
            Error::InvalidLen => "Memory buffer too small",
            Error::AlreadyOwned => "Platform is already owned",
            Error::InvalidCertificate => "Invalid certificate",
            Error::PolicyFailure => "Policy failure",
            Error::Inactive => "Guest is inactive",
            Error::InvalidAddress => "Provided address is invalid",
            Error::BadSignature => "Provided signature is invalid",
            Error::BadMeasurement => "Provided measurement is invalid",
            Error::AsidOwned => "ASID is already owned",
            Error::InvalidAsid => "ASID is invalid",
            Error::WbinvdRequired => "WBINVD instruction required",
            Error::DfFlushRequired => "DF_FLUSH invocation required",
            Error::InvalidGuest => "Guest handle is invalid",
            Error::InvalidCommand => "Issued command is invalid",
            Error::Active => "Guest is active",
            Error::HardwarePlatform => {
                "Hardware condition occured, safe to re-allocate parameter buffers"
            }
            Error::HardwareUnsafe => {
                "Hardware condition occured, unsafe to re-allocate parameter buffers"
            }
            Error::Unsupported => "Feature is unsupported",
            Error::InvalidParam => "Given parameter is invalid",
            Error::ResourceLimit => {
                "SEV firmware has run out of required resources to carry out command"
            }
            Error::SecureDataInvalid => "SEV platform observed a failed integrity check",
        };
        write!(f, "{err_description}")
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(error: io::Error) -> Error {
        Error::IoError(error)
    }
}

impl From<io::Error> for Indeterminate<Error> {
    #[inline]
    fn from(error: io::Error) -> Indeterminate<Error> {
        Indeterminate::Known(error.into())
    }
}

impl From<Indeterminate<Error>> for io::Error {
    #[inline]
    fn from(indeterminate: Indeterminate<Error>) -> io::Error {
        match indeterminate {
            Indeterminate::Known(e) => io::Error::new(io::ErrorKind::Other, e),
            Indeterminate::Unknown => io::Error::new(io::ErrorKind::Other, "unknown SEV error"),
        }
    }
}

impl From<u32> for Indeterminate<Error> {
    #[inline]
    fn from(error: u32) -> Indeterminate<Error> {
        Indeterminate::Known(match error {
            0 => io::Error::last_os_error().into(),
            1 => Error::InvalidPlatformState,
            2 => Error::InvalidGuestState,
            3 => Error::InvalidConfig,
            4 => Error::InvalidLen,
            5 => Error::AlreadyOwned,
            6 => Error::InvalidCertificate,
            7 => Error::PolicyFailure,
            8 => Error::Inactive,
            9 => Error::InvalidAddress,
            10 => Error::BadSignature,
            11 => Error::BadMeasurement,
            12 => Error::AsidOwned,
            13 => Error::InvalidAsid,
            14 => Error::WbinvdRequired,
            15 => Error::DfFlushRequired,
            16 => Error::InvalidGuest,
            17 => Error::InvalidCommand,
            18 => Error::Active,
            19 => Error::HardwarePlatform,
            20 => Error::HardwareUnsafe,
            21 => Error::Unsupported,
            22 => Error::InvalidParam,
            23 => Error::ResourceLimit,
            24 => Error::SecureDataInvalid,
            _ => return Indeterminate::Unknown,
        })
    }
}

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

    /// Get a copy of the data stored in the entry.
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
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

impl Default for CertTableEntry {
    fn default() -> Self {
        Self {
            cert_type: SnpCertType::Empty,
            data: Default::default(),
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
/// Certificates to send to the PSP.
pub struct CertTable {
    /// A vector of [`CertTableEntry`].
    pub entries: Vec<CertTableEntry>,
}

impl CertTable {
    /// Default Constructor for the Certificate Table.
    pub fn new(mut entries: Vec<CertTableEntry>) -> Self {
        let last_entry: Option<&CertTableEntry> = entries.last();

        // Make sure the last entry is an empty one, or it will not work as expected.
        if last_entry.is_some() && last_entry.unwrap().cert_type != SnpCertType::Empty {
            entries.push(CertTableEntry::default());
        }

        Self { entries }
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
    pub certs: Option<CertTable>,

    /// SET:
    ///     Length of the certificates.
    ///
    /// GET:
    ///     Length of the buffer which will hold the fetched certificates.
    pub certs_buf: u32,
}

impl SnpExtConfig {
    /// Used to update the PSP with the cerificates provided.
    pub fn update_certs_only(certificates: CertTable) -> Result<Self, SnpCertError> {
        let mut certs_buffer: usize = 4096;
        let certs_length: usize = certificates
            .entries
            .iter()
            .map(|entry| entry.data().len())
            .sum();

        while certs_length > certs_buffer {
            certs_buffer += _4K_PAGE;
        }

        Ok(Self {
            config: None,
            certs: Some(certificates),
            certs_buf: certs_buffer as u32,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{CertTable, CertTableEntry, SnpCertType, SnpConfig, SnpExtConfig};
    use crate::firmware::linux::host::types::TcbVersion;

    fn build_ext_config() -> SnpExtConfig {
        let test_cfg: SnpConfig = SnpConfig::new(TcbVersion::new(2, 0, 6, 39), 31);

        let cert_table: CertTable = CertTable {
            entries: vec![CertTableEntry::new(SnpCertType::ARK, vec![1; 28])],
        };

        SnpExtConfig {
            config: Some(test_cfg),
            certs: Some(cert_table),
            certs_buf: 4096,
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
        let cert_table: CertTable = CertTable {
            entries: vec![CertTableEntry::new(SnpCertType::ARK, vec![1; 28])],
        };

        let cfg: SnpExtConfig = build_ext_config();
        assert_eq!(cfg.certs, Some(cert_table));
    }
}
