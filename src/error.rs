// SPDX-License-Identifier: Apache-2.0

use bincode;
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack;
use std::{
    array::TryFromSliceError,
    convert::From,
    error,
    fmt::{Debug, Display},
    io,
};

#[cfg(feature = "openssl")]
use rdrand::ErrorCode;

use std::os::raw::c_int;

#[cfg(feature = "openssl")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Used for representing known errors when handling snp::Certificates.
pub enum CertFormatError {
    /// Unknown certificate format identified.
    UnknownFormat,
}

#[cfg(feature = "openssl")]
impl std::error::Error for CertFormatError {}

#[cfg(feature = "openssl")]
impl std::fmt::Display for CertFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFormat => write!(f, "Unknown Certificate Format Encountered."),
        }
    }
}

/// An error representingthe upper 32 bits of a SW_EXITINFO2 field set by the VMM.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VmmError {
    /// If there are not enough guest pages to hold the certificate table
    /// and certificate data, the hypervisor will return the required number
    /// of pages needed to hold the certificate table and certificate data
    /// in the RBX register and set the SW_EXITINFO2 field to
    /// 0x0000000100000000.
    InvalidCertificatePageLength = 0x1, // Upper 32 bits.

    /// It is not expected that a guest would issue many Guest Request NAE
    /// events. However, access to the SNP firmware is a sequential and
    /// synchronous operation. To avoid the possibility of a guest creating a
    /// denial-of-service attack against the SNP firmware, it is recommended
    /// that some form of rate limiting be implemented should it be detected
    /// that a high number of Guest Request NAE events are being issued. To
    /// allow for this, the hypervisor may set the SW_EXITINFO2 field to
    /// 0x0000000200000000, which will inform the guest to retry the request.
    RateLimitRetryRequest = 0x2, // Upper 32 bits

    /// Nothing more implemented yet.
    Unknown,
}

/// Use the default implementations for std::error::Error here.
impl error::Error for VmmError {}

impl From<u32> for VmmError {
    /// Takes a raw u32 and translates it into the correlated [VmmError](self::VmmError)
    /// type.
    ///
    /// * value - The raw u32 value which we would like to interpret.
    ///
    /// # Example
    ///
    /// ```
    /// use sev::error::VmmError;
    /// let raw_value: u32 = 0x1u32;
    /// let outcome: VmmError = VmmError::from(raw_value);
    /// assert_eq!(outcome, VmmError::InvalidCertificatePageLength);
    /// ```
    fn from(value: u32) -> Self {
        match value {
            0x1 => VmmError::InvalidCertificatePageLength,
            0x2 => VmmError::RateLimitRetryRequest,
            _ => VmmError::Unknown,
        }
    }
}

impl From<u64> for VmmError {
    /// Takes a raw u64 and translates it into the correlated [VmmError](self::VmmError)
    /// type.
    ///
    /// * value - The raw u64 value which we would like to interpret.
    ///
    /// # Example
    ///
    /// ```
    /// use sev::error::VmmError;
    /// let raw_value: u64 = 0x100000000;
    /// let outcome: VmmError = VmmError::from(raw_value);
    /// assert_eq!(outcome, VmmError::InvalidCertificatePageLength);
    /// ```
    fn from(value: u64) -> Self {
        ((value >> 0x20) as u32).into()
    }
}

impl Display for VmmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmmError::InvalidCertificatePageLength => write!(f, "An invalid number of pages was provided to copy the certificate table and certificate data to userspace."),
            VmmError::RateLimitRetryRequest => write!(f, "The AMD Secure Processor detected a possible denial-of-service. Please retry your request."),
            VmmError::Unknown => write!(f, "An unknown VMM error was encountered!"),
        }
    }
}

/// The raw firmware error.
#[derive(Debug)]
pub(crate) struct RawFwError(pub(crate) u64);

impl std::error::Error for RawFwError {}

impl From<u64> for RawFwError {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl PartialEq for RawFwError {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<RawFwError> for (u32, u32) {
    fn from(value: RawFwError) -> Self {
        ((value.0 >> 0x20) as u32, value.0 as u32)
    }
}

impl From<RawFwError> for (VmmError, SevError) {
    fn from(value: RawFwError) -> Self {
        (((value.0 >> 0x20) as u32).into(), (value.0 as u32).into())
    }
}

impl Display for RawFwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawFwError: {}", self.0)
    }
}

/// Error conditions returned by the SEV platform or by layers above it
/// (i.e., the Linux kernel).
///
/// These error conditions are documented in the AMD SEV API spec, but
/// their documentation has been copied here for completeness.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum SevError {
    /// The platform state is invalid for this command.
    InvalidPlatformState = 0x0001,

    /// The guest state is invalid for this command.
    InvalidGuestState = 0x0002,

    /// The platform configuration is invalid.
    InvalidConfig = 0x0003,

    /// A memory buffer is too small.
    InvalidLen = 0x0004,

    /// The platform is already owned.
    AlreadyOwned = 0x0005,

    /// The certificate is invalid.
    InvalidCertificate = 0x0006,

    /// Request is not allowed by guest policy.
    PolicyFailure = 0x0007,

    /// The guest is inactive.
    Inactive = 0x0008,

    /// The address provided is invalid.
    InvalidAddress = 0x0009,

    /// The provided signature is invalid.
    BadSignature = 0x000A,

    /// The provided measurement is invalid.
    BadMeasurement = 0x000B,

    /// The ASID is already owned.
    AsidOwned = 0x000C,

    /// The ASID is invalid.
    InvalidAsid = 0x000D,

    /// WBINVD instruction required.
    WbinvdRequired = 0x000E,

    /// `DF_FLUSH` invocation required.
    DfFlushRequired = 0x000F,

    /// The guest handle is invalid.
    InvalidGuest = 0x0010,

    /// The command issued is invalid.
    InvalidCommand = 0x0011,

    /// The guest is active.
    Active = 0x0012,

    /// A hardware condition has occurred affecting the platform. It is safe
    /// to re-allocate parameter buffers.
    HardwarePlatform = 0x0013,

    /// A hardware condition has occurred affecting the platform. Re-allocating
    /// parameter buffers is not safe.
    HardwareUnsafe = 0x0014,

    /// Feature is unsupported.
    Unsupported = 0x0015,

    /// A given parameter is invalid.
    InvalidParam = 0x0016,

    /// The SEV firmware has run out of a resource required to carry out the
    /// command.
    ResourceLimit = 0x0017,

    /// The SEV platform observed a failed integrity check.
    SecureDataInvalid = 0x0018,

    /// The RMP page size is incorrect.
    InvalidPageSize = 0x0019,

    /// The RMP page state is incorrect
    InvalidPageState = 0x001A,

    /// The metadata entry is invalid.
    InvalidMdataEntry = 0x001B,

    /// The page ownership is incorrect
    InvalidPageOwner = 0x001C,

    /// The AEAD algorithm would have overflowed
    AEADOFlow = 0x001D,

    /// A Mailbox mode command was sent while the SEV FW was in Ring Buffer
    /// mode. Ring Buffer mode has been exited; the Mailbox mode command
    /// has been ignored. Retry is recommended.
    RbModeExited = 0x001F, // 0x001F

    /// The RMP must be reinitialized.
    RMPInitRequired = 0x0020, // 0x0020

    /// SVN of provided image is lower than the committed SVN.
    BadSvn = 0x0021,

    /// Firmware version anti-rollback.
    BadVersion = 0x0022,

    /// An invocation of SNP_SHUTDOWN is required to complete this action.
    ShutdownRequired = 0x0023,

    /// Update of the firmware internal state or a guest context page has failed.
    UpdateFailed = 0x0024,

    /// Installation of the committed firmware image required
    RestoreRequired = 0x0025,

    /// The RMP initialization failed.
    RMPInitFailed = 0x0026,

    /// The key requested is invalid, not present, or not allowed.
    InvalidKey = 0x0027,

    /// Unknown status code
    UnknownError = 0x0000,
}

impl std::fmt::Display for SevError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let code = *self as u32;
        match self {
            SevError::InvalidPlatformState => write!(f,"Status Code: 0x{:x}: Invalid platform state.", code),
            SevError::InvalidGuestState => write!(f,"Status Code: 0x{:x}: Invalid guest state.", code),
            SevError::InvalidConfig => write!(f,"Status Code: 0x{:x}: Platform configuration invalid.", code),
            SevError::InvalidLen => write!(f,"Status Code: 0x{:x}: Memory buffer too small.", code),
            SevError::AlreadyOwned => write!(f,"Status Code: 0x{:x}: Platform is already owned.", code),
            SevError::InvalidCertificate => write!(f,"Status Code: 0x{:x}: Invalid certificate.", code),
            SevError::PolicyFailure => write!(f,"Status Code: 0x{:x}: Policy failure.", code),
            SevError::Inactive => write!(f,"Status Code: 0x{:x}: Guest is inactive.", code),
            SevError::InvalidAddress => write!(f,"Status Code: 0x{:x}: Provided address is invalid.", code),
            SevError::BadSignature => write!(f,"Status Code: 0x{:x}: Provided signature is invalid.", code),
            SevError::BadMeasurement => write!(f,"Status Code: 0x{:x}: Provided measurement is invalid.", code),
            SevError::AsidOwned => write!(f,"Status Code: 0x{:x}: ASID is already owned.", code),
            SevError::InvalidAsid => write!(f,"Status Code: 0x{:x}: ASID is invalid.", code),
            SevError::WbinvdRequired => write!(f,"Status Code: 0x{:x}: WBINVD instruction required.", code),
            SevError::DfFlushRequired => write!(f,"Status Code: 0x{:x}: DF_FLUSH invocation required.", code),
            SevError::InvalidGuest => write!(f,"Status Code: 0x{:x}: Guest handle is invalid.", code),
            SevError::InvalidCommand => write!(f,"Status Code: 0x{:x}: Issued command is invalid.", code),
            SevError::Active => write!(f,"Status Code: 0x{:x}: Guest is active.", code),
            SevError::HardwarePlatform => {
                write!(f,"Status Code: 0x{:x}: Hardware condition occured, safe to re-allocate parameter buffers.", code)
            }
            SevError::HardwareUnsafe => {
                write!(f,"Status Code: 0x{:x}: Hardware condition occured, unsafe to re-allocate parameter buffers.", code)
            }
            SevError::Unsupported => write!(f,"Status Code: 0x{:x}: Feature is unsupported.", code),
            SevError::InvalidParam => write!(f,"Status Code: 0x{:x}: Given parameter is invalid.", code),
            SevError::ResourceLimit => {
                write!(f,"Status Code: 0x{:x}: SEV firmware has run out of required resources to carry out command.", code)
            }
            SevError::SecureDataInvalid => write!(f,"Status Code: 0x{:x}: SEV platform observed a failed integrity check.", code),
            SevError::InvalidPageSize => write!(f,"Status Code: 0x{:x}: The RMP page size is incorrect.", code),
            SevError::InvalidPageState => write!(f,"Status Code: 0x{:x}: The RMP page state is incorrect.", code),
            SevError::InvalidMdataEntry => write!(f,"Status Code: 0x{:x}: The metadata entry is invalid.", code),
            SevError::InvalidPageOwner => write!(f,"Status Code: 0x{:x}: The page ownership is incorrect.", code),
            SevError::AEADOFlow => write!(f,"Status Code: 0x{:x}: The AEAD algorithm would have overflowed.", code),
            SevError::RbModeExited => write!(f,"Status Code: 0x{:x}: A Mailbox mode command was sent while the SEV FW was in Ring Buffer \
                                    mode. Ring Buffer mode has been exited; the Mailbox mode command has \
                                    been ignored. Retry is recommended.", code),
            SevError::RMPInitRequired => write!(f,"Status Code: 0x{:x}: The RMP must be reinitialized.", code),
            SevError::BadSvn => write!(f,"Status Code: 0x{:x}: SVN of provided image is lower than the committed SVN.", code),
            SevError::BadVersion => write!(f,"Status Code: 0x{:x}: Firmware version anti-rollback.", code),
            SevError::ShutdownRequired => write!(f,"Status Code: 0x{:x}: An invocation of SNP_SHUTDOWN is required to complete this action.", code),
            SevError::UpdateFailed => write!(f,"Status Code: 0x{:x}: Update of the firmware internal state or a guest context page has failed.", code),
            SevError::RestoreRequired => write!(f,"Status Code: 0x{:x}: Installation of the committed firmware image required.", code),
            SevError::RMPInitFailed => write!(f,"Status Code: 0x{:x}: The RMP initialization failed.", code),
            SevError::InvalidKey => write!(f,"Status Code: 0x{:x}: The key requested is invalid, not present, or not allowed.", code),
            SevError::UnknownError => write!(f,"Unknown SEV Error"),
        }
    }
}

impl From<u64> for SevError {
    fn from(value: u64) -> Self {
        Self::from(value as u32)
    }
}

impl From<u32> for SevError {
    #[inline]
    fn from(error: u32) -> SevError {
        match error {
            0x01 => SevError::InvalidPlatformState,
            0x02 => SevError::InvalidGuestState,
            0x03 => SevError::InvalidConfig,
            0x04 => SevError::InvalidLen,
            0x05 => SevError::AlreadyOwned,
            0x06 => SevError::InvalidCertificate,
            0x07 => SevError::PolicyFailure,
            0x08 => SevError::Inactive,
            0x09 => SevError::InvalidAddress,
            0x0A => SevError::BadSignature,
            0x0B => SevError::BadMeasurement,
            0x0C => SevError::AsidOwned,
            0x0D => SevError::InvalidAsid,
            0x0E => SevError::WbinvdRequired,
            0x0F => SevError::DfFlushRequired,
            0x10 => SevError::InvalidGuest,
            0x11 => SevError::InvalidCommand,
            0x12 => SevError::Active,
            0x13 => SevError::HardwarePlatform,
            0x14 => SevError::HardwareUnsafe,
            0x15 => SevError::Unsupported,
            0x16 => SevError::InvalidParam,
            0x17 => SevError::ResourceLimit,
            0x18 => SevError::SecureDataInvalid,
            0x19 => SevError::InvalidPageSize,
            0x1A => SevError::InvalidPageState,
            0x1B => SevError::InvalidMdataEntry,
            0x1C => SevError::InvalidPageOwner,
            0x1D => SevError::AEADOFlow,
            0x1F => SevError::RbModeExited,
            0x20 => SevError::RMPInitRequired,
            0x21 => SevError::BadSvn,
            0x22 => SevError::BadVersion,
            0x23 => SevError::ShutdownRequired,
            0x24 => SevError::UpdateFailed,
            0x25 => SevError::RestoreRequired,
            0x26 => SevError::RMPInitFailed,
            0x27 => SevError::InvalidKey,
            _ => SevError::UnknownError,
        }
    }
}

impl From<SevError> for c_int {
    fn from(err: SevError) -> Self {
        match err {
            SevError::InvalidPlatformState => 0x01,
            SevError::InvalidGuestState => 0x02,
            SevError::InvalidConfig => 0x03,
            SevError::InvalidLen => 0x04,
            SevError::AlreadyOwned => 0x05,
            SevError::InvalidCertificate => 0x06,
            SevError::PolicyFailure => 0x07,
            SevError::Inactive => 0x08,
            SevError::InvalidAddress => 0x09,
            SevError::BadSignature => 0x0A,
            SevError::BadMeasurement => 0x0B,
            SevError::AsidOwned => 0x0C,
            SevError::InvalidAsid => 0x0D,
            SevError::WbinvdRequired => 0x0E,
            SevError::DfFlushRequired => 0x0F,
            SevError::InvalidGuest => 0x10,
            SevError::InvalidCommand => 0x11,
            SevError::Active => 0x12,
            SevError::HardwarePlatform => 0x13,
            SevError::HardwareUnsafe => 0x14,
            SevError::Unsupported => 0x15,
            SevError::InvalidParam => 0x16,
            SevError::ResourceLimit => 0x17,
            SevError::SecureDataInvalid => 0x18,
            SevError::InvalidPageSize => 0x19,
            SevError::InvalidPageState => 0x1A,
            SevError::InvalidMdataEntry => 0x1B,
            SevError::InvalidPageOwner => 0x1C,
            SevError::AEADOFlow => 0x1D,
            SevError::RbModeExited => 0x1F,
            SevError::RMPInitRequired => 0x20,
            SevError::BadSvn => 0x21,
            SevError::BadVersion => 0x22,
            SevError::ShutdownRequired => 0x23,
            SevError::UpdateFailed => 0x24,
            SevError::RestoreRequired => 0x25,
            SevError::RMPInitFailed => 0x26,
            SevError::InvalidKey => 0x27,
            SevError::UnknownError => -1,
        }
    }
}

impl std::error::Error for SevError {}

/// There are a number of error conditions that can occur between this
/// layer all the way down to the SEV platform. Most of these cases have
/// been enumerated; however, there is a possibility that some error
/// conditions are not encapsulated here.
#[derive(Debug)]
pub enum FirmwareError {
    /// The error condition is known.
    KnownSevError(SevError),

    /// The error condition is unknown.
    UnknownSevError(u32),

    /// IO Error
    IoError(std::io::Error),
}

impl error::Error for FirmwareError {}

impl Display for FirmwareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_description = match self {
            FirmwareError::KnownSevError(error) => format!("Known SEV FW Error: {error}"),
            FirmwareError::UnknownSevError(code) => {
                format!("Unknown SEV FW Error Encountered: {code}")
            }
            FirmwareError::IoError(error) => format!("IO Error Encountered: {error}"),
        };

        write!(f, "{err_description}")
    }
}

impl std::convert::From<SevError> for FirmwareError {
    fn from(sev_error: SevError) -> Self {
        match sev_error {
            SevError::UnknownError => FirmwareError::UnknownSevError(sev_error as u32),
            _ => FirmwareError::KnownSevError(sev_error),
        }
    }
}

impl From<io::Error> for FirmwareError {
    #[inline]
    fn from(error: io::Error) -> FirmwareError {
        FirmwareError::IoError(error)
    }
}

impl From<u64> for FirmwareError {
    fn from(value: u64) -> Self {
        Self::from(value as u32)
    }
}

impl From<u32> for FirmwareError {
    #[inline]
    fn from(error: u32) -> FirmwareError {
        match error {
            0x00 => FirmwareError::IoError(io::Error::last_os_error()),
            0x01..0x027 => FirmwareError::KnownSevError(error.into()),
            _ => FirmwareError::UnknownSevError(error),
        }
    }
}

impl From<FirmwareError> for c_int {
    fn from(err: FirmwareError) -> Self {
        match err {
            FirmwareError::UnknownSevError(_) | FirmwareError::IoError(_) => -0x01,
            FirmwareError::KnownSevError(e) => e.into(),
        }
    }
}

#[derive(Debug)]
/// Wrapper Error for Firmware or User API Errors
pub enum UserApiError {
    /// Sev Firmware related errors.
    FirmwareError(FirmwareError),

    /// IO related errors
    IOError(io::Error),

    /// User API related errors.
    ApiError(CertError),

    /// Errors returned by the VMM via ioctl().
    VmmError(VmmError),

    /// Uuid parsing errors.
    UuidError(uuid::Error),

    /// VLEK Hashstick errors.
    HashstickError(HashstickError),

    /// Invalid VMPL.
    VmplError,

    /// Attestation Report Error
    AttestationReportError(AttestationReportError),

    /// Unknown error
    Unknown,
}

impl error::Error for UserApiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::ApiError(uapi_error) => Some(uapi_error),
            Self::FirmwareError(firmware_error) => Some(firmware_error),
            Self::IOError(io_error) => Some(io_error),
            Self::UuidError(uuid_error) => Some(uuid_error),
            Self::VmmError(vmm_error) => Some(vmm_error),
            Self::HashstickError(hashstick_error) => Some(hashstick_error),
            Self::VmplError => None,
            Self::AttestationReportError(attestation_error) => Some(attestation_error),
            Self::Unknown => None,
        }
    }
}

impl std::fmt::Display for UserApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let err_msg: String = match self {
            Self::FirmwareError(error) => format!("Firmware Error Encountered: {error}"),
            Self::IOError(error) => format!("I/O Error Encountered: {error}"),
            Self::ApiError(error) => format!("Certificate Error Encountered: {error}"),
            Self::UuidError(error) => format!("UUID Error Encountered: {error}"),
            Self::VmmError(error) => format!("VMM Error Encountered: {error}"),
            Self::HashstickError(error) => format!("VLEK Hashstick Error Encountered: {error}"),
            Self::VmplError => "Invalid VM Permission Level (VMPL)".to_string(),
            Self::AttestationReportError(error) => {
                format!("Attestation Report Error Encountered: {error}")
            }
            Self::Unknown => "Unknown Error Encountered!".to_string(),
        };
        write!(f, "{err_msg}")
    }
}

impl std::convert::From<HashstickError> for UserApiError {
    fn from(value: HashstickError) -> Self {
        Self::HashstickError(value)
    }
}

impl std::convert::From<VmmError> for UserApiError {
    fn from(value: VmmError) -> Self {
        Self::VmmError(value)
    }
}

impl std::convert::From<uuid::Error> for UserApiError {
    fn from(uuid_error: uuid::Error) -> Self {
        Self::UuidError(uuid_error)
    }
}

impl std::convert::From<FirmwareError> for UserApiError {
    fn from(firmware_error: FirmwareError) -> Self {
        Self::FirmwareError(firmware_error)
    }
}

impl std::convert::From<SevError> for UserApiError {
    fn from(sev_error: SevError) -> Self {
        Self::FirmwareError(sev_error.into())
    }
}

impl std::convert::From<std::io::Error> for UserApiError {
    fn from(io_error: std::io::Error) -> Self {
        Self::IOError(io_error)
    }
}

impl From<UserApiError> for io::Error {
    fn from(value: UserApiError) -> Self {
        io::Error::new(io::ErrorKind::Other, value)
    }
}

impl std::convert::From<CertError> for UserApiError {
    fn from(cert_error: CertError) -> Self {
        Self::ApiError(cert_error)
    }
}

impl std::convert::From<AttestationReportError> for UserApiError {
    fn from(attestation_error: AttestationReportError) -> Self {
        Self::AttestationReportError(attestation_error)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Errors which may be encountered when handling Version Loaded Endorsement Keys
/// (VLEK) Hashsticks.
pub enum HashstickError {
    /// Hashstick length does not match what was specified in the buffer.
    InvalidLength,

    /// No hashstick was provided
    EmptyHashstickBuffer,

    /// Unknown Error.
    UnknownError,
}

impl std::error::Error for HashstickError {}

impl std::fmt::Display for HashstickError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashstickError::InvalidLength => {
                write!(
                    f,
                    "VLEK hashstick is an invalid length. Should be 432 bytes in size."
                )
            }
            HashstickError::EmptyHashstickBuffer => write!(f, "Hashstick buffer is empty."),
            HashstickError::UnknownError => {
                write!(
                    f,
                    "Unknown error encountered when handling the VLEK Hashstick."
                )
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Errors which may be encountered through misuse of the User API.
pub enum CertError {
    /// Malformed GUID.
    InvalidGUID,

    /// Malformed Page Alignment
    PageMisalignment,

    /// Invalid Buffer Size
    BufferOverflow,

    /// No certificates were set by the Host.
    EmptyCertBuffer,

    /// Unknown Error.
    UnknownError,
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CertError::InvalidGUID => write!(f, "Invalid GUID provided in certificate chain."),
            CertError::PageMisalignment => {
                write!(f, "Certificate Buffer not aligned with 4K Pages.")
            }
            CertError::BufferOverflow => {
                write!(f, "Buffer overflow prevented: Bytes provided exceed space allocated for the buffer provided.")
            }
            CertError::UnknownError => {
                write!(f, "Unknown Error encountered within the certificate chain.")
            }
            CertError::EmptyCertBuffer => {
                write!(
                    f,
                    "No certificates were provided by the host, please contact your CSP."
                )
            }
        }
    }
}

impl error::Error for CertError {}

#[derive(Debug)]
/// Errors which may be encountered when handling attestation reports
pub enum AttestationReportError {
    /// Bincode Error Handling
    BincodeError(bincode::ErrorKind),

    /// Unsuported Attestation Report Version
    UnsupportedReportVersion(u32),

    /// Field is not supported in the current version of the Attestation Report
    UnsupportedField(String),

    /// MASK_CHIP_ID enabled
    MaskedChipId,
}

impl std::fmt::Display for AttestationReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AttestationReportError::BincodeError(e) => write!(f, "Bincode error encountered: {e}"),
            AttestationReportError::MaskedChipId => write!(f, "MASK_CHIP_ID is enabled, preventing the identification of the CPU generation."),
            AttestationReportError::UnsupportedReportVersion(version) => write!(f, "The encountered Attestation Report version {version} is not supported by the library yet."),
            AttestationReportError::UnsupportedField(field) => write!(f,"The field {field} is not supported in the provided Attestation Report version"),
        }
    }
}

impl From<AttestationReportError> for std::io::Error {
    fn from(value: AttestationReportError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, value)
    }
}

impl std::convert::From<bincode::ErrorKind> for AttestationReportError {
    fn from(value: bincode::ErrorKind) -> Self {
        Self::BincodeError(value)
    }
}

impl error::Error for AttestationReportError {}

#[derive(Debug)]
/// Errors which may be encountered when building custom guest context.
pub enum GCTXError {
    /// Malformed guest context page.
    InvalidPageSize(usize, usize),

    /// Block size data was the incorrect size
    InvalidBlockSize,

    /// Missing data to do page update
    MissingData,

    /// Missing block size
    MissingBlockSize,

    /// Unknown Error.
    UnknownError,
}

impl std::fmt::Display for GCTXError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GCTXError::InvalidPageSize(actual, expected) => write!(
                f,
                "Page information was not the correct length ({actual} vs {expected})"
            ),
            GCTXError::InvalidBlockSize => {
                write!(f, "Provided data does not conform to a 4096 block size")
            }
            GCTXError::MissingData => {
                write!(f, "Did not provide data to perform page update")
            }
            GCTXError::MissingBlockSize => {
                write!(f, "Did not provide block size to perform page update")
            }
            GCTXError::UnknownError => write!(f, "An unknown Guest Context error encountered"),
        }
    }
}

impl std::error::Error for GCTXError {}

#[derive(Debug)]
/// Errors which may be encountered when handling OVMF data
pub enum OVMFError {
    /// An invalid section type was provided for OVMF METADATA
    InvalidSectionType,

    /// Part of the SEV METADATA failed verification
    SEVMetadataVerification(String),

    /// Desired entry is missing from table
    EntryMissingInTable(String),

    /// Failed to get item from table
    GetTableItemError,

    /// Invalid Entry Size was provided
    InvalidSize(String, usize, usize),

    /// GUID doesn't match expected GUID
    MismatchingGUID,

    /// Unknown Error.
    UnknownError,
}

impl std::fmt::Display for OVMFError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OVMFError::InvalidSectionType => write!(f, "An invalid section type was found"),
            OVMFError::SEVMetadataVerification(section) => {
                write!(f, "Wrong SEV metadata {section}")
            }
            OVMFError::EntryMissingInTable(entry) => {
                write!(f, "Can't find {entry} entry in OVMF table")
            }
            OVMFError::GetTableItemError => {
                write!(f, "OVMF table failed to return item")
            }
            OVMFError::InvalidSize(entry, actual, expected) => {
                write!(f, "Invalid size of {entry}: {actual} < {expected}")
            }
            OVMFError::MismatchingGUID => {
                write!(f, "OVMF table footer GUID does not match expected GUID")
            }
            OVMFError::UnknownError => write!(f, "An unknown OVMF error encountered"),
        }
    }
}

impl std::error::Error for OVMFError {}

/// Errors which may be encountered when building SEV hashes.
#[derive(Debug)]
pub enum SevHashError {
    /// Provided page has invalid size
    InvalidSize(usize, usize),

    /// Provided page has invalid offset
    InvalidOffset(usize, usize),

    /// Unknown Error.
    UnknownError,
}

impl std::fmt::Display for SevHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SevHashError::InvalidOffset(actual, expected) => {
                write!(f, "Invalid page Offset: {actual} vs {expected}")
            }
            SevHashError::InvalidSize(actual, expected) => {
                write!(f, "Invalid page Size: {actual} vs {expected}")
            }
            SevHashError::UnknownError => write!(f, "An unknown SEV Hashing error encountered"),
        }
    }
}

impl std::error::Error for SevHashError {}

/// Possible errors when working with the large array type
#[derive(Debug)]
pub enum ArrayError {
    /// Error when trying from slice
    SliceError(TryFromSliceError),

    /// Error when converting from vector
    VectorError(String),
}

impl std::fmt::Display for ArrayError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ArrayError::SliceError(error) => {
                write!(f, "Error when trying from slice: {error}")
            }
            ArrayError::VectorError(error) => {
                write!(f, "Error when trying from vector: {error}")
            }
        }
    }
}

impl std::error::Error for ArrayError {}

impl std::convert::From<TryFromSliceError> for ArrayError {
    fn from(value: TryFromSliceError) -> Self {
        Self::SliceError(value)
    }
}

/// Errors when calculating the ID BLOCK
#[derive(Debug)]
pub enum IdBlockError {
    #[cfg(all(feature = "snp", feature = "openssl"))]
    /// TryFrom Slice Error handling
    CryptoErrorStack(openssl::error::ErrorStack),

    /// Large Array Error handling
    LargeArrayError(ArrayError),

    /// File Error Handling
    FileError(std::io::Error),

    /// Bincode Error Handling
    BincodeError(bincode::ErrorKind),

    /// TryFrom Slice Error handling
    FromSliceError(TryFromSliceError),

    /// Error from when handling SEV Curve algorithm
    SevCurveError(),

    /// Error when handling SEV ECDSA Signature
    SevEcsdsaSigError(String),
}

impl std::fmt::Display for IdBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            #[cfg(all(feature = "snp", feature = "openssl"))]
            IdBlockError::CryptoErrorStack(e) => write!(f, "Error when with OPENSSL: {e}"),
            IdBlockError::LargeArrayError(e) => write!(f, "{e}"),
            IdBlockError::FileError(e) => write!(f, "Failed handling file: {e}"),
            IdBlockError::BincodeError(e) => write!(f, "Bincode error encountered: {e}"),
            IdBlockError::FromSliceError(e) => write!(f, "Error converting slice: {e}"),
            IdBlockError::SevCurveError() => {
                write!(f, "Wrong curve used in the provided private key")
            }
            IdBlockError::SevEcsdsaSigError(msg) => {
                write!(f, "Error validation SEV signature: {msg}")
            }
        }
    }
}

impl std::error::Error for IdBlockError {}

#[cfg(all(feature = "snp", feature = "openssl"))]
impl std::convert::From<openssl::error::ErrorStack> for IdBlockError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::CryptoErrorStack(value)
    }
}

impl std::convert::From<ArrayError> for IdBlockError {
    fn from(value: ArrayError) -> Self {
        Self::LargeArrayError(value)
    }
}

impl std::convert::From<std::io::Error> for IdBlockError {
    fn from(value: std::io::Error) -> Self {
        Self::FileError(value)
    }
}

impl std::convert::From<bincode::ErrorKind> for IdBlockError {
    fn from(value: bincode::ErrorKind) -> Self {
        Self::BincodeError(value)
    }
}

impl std::convert::From<TryFromSliceError> for IdBlockError {
    fn from(value: TryFromSliceError) -> Self {
        Self::FromSliceError(value)
    }
}

/// Errors which may be encountered when calculating the guest measurement.
#[derive(Debug)]
pub enum MeasurementError {
    /// TryFrom Slice Error handling
    FromSliceError(TryFromSliceError),

    /// UUID Error handling
    UUIDError(uuid::Error),

    /// Bincode Error Handling
    BincodeError(bincode::ErrorKind),

    /// File Error Handling
    FileError(std::io::Error),

    /// Vec from hex Error Handling
    FromHexError(hex::FromHexError),

    /// Guest Context Error Handling
    GCTXError(GCTXError),

    /// OVMF Error Handling
    OVMFError(OVMFError),

    /// SEV Hash Error Handling
    SevHashError(SevHashError),

    /// Id Block Error Handling
    IdBlockError(IdBlockError),

    /// Large Array Error handling
    LargeArrayError(ArrayError),

    /// Invalid VCPU provided
    InvalidVcpuTypeError(String),

    /// Invalid VCPU Signature provided
    InvalidVcpuSignatureError(String),

    /// Invalid VMM Provided
    InvalidVmmError(String),

    /// Invalid SEV Mode provided
    InvalidSevModeError(String),

    /// OVMF doesn't support kernel measurement
    InvalidOvmfKernelError,

    /// OVMF is missing required section with kernel specified
    MissingSection(String),
}

impl std::fmt::Display for MeasurementError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MeasurementError::FromSliceError(e) => write!(f, "Error converting slice: {e}"),
            MeasurementError::UUIDError(e) => write!(f, "UUID Error encountered: {e}"),
            MeasurementError::BincodeError(e) => write!(f, "Bincode error encountered: {e}"),
            MeasurementError::FileError(e) => write!(f, "Failed handling file: {e}"),
            MeasurementError::FromHexError(e) => write!(f, "Converting hex to vector error: {e}"),
            MeasurementError::GCTXError(e) => write!(f, "GCTX Error Encountered: {e}"),
            MeasurementError::OVMFError(e) => write!(f, "OVMF Error Encountered: {e}"),
            MeasurementError::SevHashError(e) => write!(f, "Sev hash Error Encountered: {e}"),
            MeasurementError::IdBlockError(e) => write!(f, "Id Block Error Encountered: {e}"),
            MeasurementError::LargeArrayError(e) => {
                write!(f, "Error when handling Large arrays: {e}")
            }
            MeasurementError::InvalidVcpuTypeError(value) => {
                write!(f, "Invalid VCPU type value provided: {value}")
            }
            MeasurementError::InvalidVcpuSignatureError(value) => {
                write!(f, "Invalid VCPU signature provided: {value}")
            }
            MeasurementError::InvalidVmmError(value) => {
                write!(f, "Invalid VMM type provided: {value}")
            }
            MeasurementError::InvalidSevModeError(value) => {
                write!(f, "Invalid SEV mode provided: {value}")
            }
            MeasurementError::InvalidOvmfKernelError => write!(
                f,
                "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"
            ),
            MeasurementError::MissingSection(section) => write!(
                f,
                "Kernel specified but OVMF metadata doesn't include {section} section"
            ),
        }
    }
}

impl std::error::Error for MeasurementError {}

impl std::convert::From<TryFromSliceError> for MeasurementError {
    fn from(value: TryFromSliceError) -> Self {
        Self::FromSliceError(value)
    }
}

impl std::convert::From<uuid::Error> for MeasurementError {
    fn from(value: uuid::Error) -> Self {
        Self::UUIDError(value)
    }
}

impl std::convert::From<bincode::ErrorKind> for MeasurementError {
    fn from(value: bincode::ErrorKind) -> Self {
        Self::BincodeError(value)
    }
}

impl std::convert::From<std::io::Error> for MeasurementError {
    fn from(value: std::io::Error) -> Self {
        Self::FileError(value)
    }
}

impl std::convert::From<hex::FromHexError> for MeasurementError {
    fn from(value: hex::FromHexError) -> Self {
        Self::FromHexError(value)
    }
}

impl std::convert::From<GCTXError> for MeasurementError {
    fn from(value: GCTXError) -> Self {
        Self::GCTXError(value)
    }
}

impl std::convert::From<OVMFError> for MeasurementError {
    fn from(value: OVMFError) -> Self {
        Self::OVMFError(value)
    }
}

impl std::convert::From<SevHashError> for MeasurementError {
    fn from(value: SevHashError) -> Self {
        Self::SevHashError(value)
    }
}

impl std::convert::From<IdBlockError> for MeasurementError {
    fn from(value: IdBlockError) -> Self {
        Self::IdBlockError(value)
    }
}

impl std::convert::From<ArrayError> for MeasurementError {
    fn from(value: ArrayError) -> Self {
        Self::LargeArrayError(value)
    }
}

#[cfg(feature = "openssl")]
#[derive(Debug)]
/// Used to describe errors related to SEV-ES "Sessions".
pub enum SessionError {
    /// Errors which occur from using the rdrand crate.
    RandError(ErrorCode),

    /// OpenSSL Error Stack
    OpenSSLStack(ErrorStack),

    /// Errors occuring from IO operations.
    IOError(std::io::Error),
}

#[cfg(feature = "openssl")]
impl From<ErrorCode> for SessionError {
    fn from(value: ErrorCode) -> Self {
        Self::RandError(value)
    }
}

#[cfg(feature = "openssl")]
impl From<std::io::Error> for SessionError {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}

#[cfg(feature = "openssl")]
impl From<ErrorStack> for SessionError {
    fn from(value: ErrorStack) -> Self {
        Self::OpenSSLStack(value)
    }
}

#[cfg(test)]
mod tests {
    use bincode::ErrorKind;

    use super::*;
    use std::{
        convert::{TryFrom, TryInto},
        error::Error,
    };

    #[test]
    fn test_vmm_error_complete() {
        // Test all variants
        let variants = vec![
            (1u32, VmmError::InvalidCertificatePageLength),
            (2u32, VmmError::RateLimitRetryRequest),
            (999u32, VmmError::Unknown),
        ];

        for (code, expected) in variants {
            // Test u32 conversion
            assert_eq!(VmmError::from(code), expected);
            // Test u64 conversion
            assert_eq!(VmmError::from((code as u64) << 32), expected);
            // Test display
            assert!(!expected.to_string().is_empty());
            // Test error trait
            assert!(std::error::Error::source(&expected).is_none());
        }
    }

    #[test]
    fn test_sev_error_complete() {
        // Test all valid codes
        for code in 0x01..=0x27u32 {
            if code == 0x1E {
                continue;
            } // Skip gap
            let err = SevError::from(code);
            assert!(!matches!(err, SevError::UnknownError));

            // Test u64 conversion
            let err64 = SevError::from(code as u64);
            assert_eq!(err, err64);

            // Test display
            assert!(!err.to_string().is_empty());

            // Test c_int conversion
            let c_val: c_int = err.into();
            assert_eq!(c_val as u32, code);
        }

        // Test invalid codes
        assert_eq!(SevError::from(0u32), SevError::UnknownError);
        assert_eq!(SevError::from(0x28u32), SevError::UnknownError);
        assert!(!SevError::from(0u32).to_string().is_empty());
        assert!(!SevError::from(0x28u32).to_string().is_empty());
        let err: SevError = SevError::UnknownError;
        let c_val: c_int = err.into();
        assert_eq!(c_val as u32, u32::MAX);
    }

    #[test]
    fn test_raw_fw_error_complete() {
        let raw = RawFwError(0x100000000u64);

        // Test display and debug
        assert!(raw.to_string().contains("RawFwError: 4294967296"));
        assert!(format!("{:?}", raw).contains("RawFwError"));

        // Test From<u64>
        assert_eq!(RawFwError::from(0x100000000u64), raw);

        // Test tuple conversions
        let (upper, lower): (u32, u32) = raw.into();
        assert_eq!(upper, 1);
        assert_eq!(lower, 0);

        let raw2 = RawFwError(0x100000000u64);
        let (vmm, _sev): (VmmError, SevError) = raw2.into();
        assert_eq!(vmm, VmmError::InvalidCertificatePageLength);
    }

    #[test]
    fn test_firmware_error_complete() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let variants = vec![
            FirmwareError::IoError(io_err),
            FirmwareError::KnownSevError(SevError::InvalidPlatformState),
            FirmwareError::UnknownSevError(999),
        ];

        for err in variants {
            // Test display
            assert!(!err.to_string().is_empty());

            // Test c_int conversion
            let c_val: c_int = err.into();
            assert!(c_val == -1 || c_val > 0);
        }

        // Test conversions
        let from_u32: FirmwareError = 0x0u32.into();
        assert!(matches!(from_u32, FirmwareError::IoError(_)));
        let from_u32: FirmwareError = 0x1u32.into();
        assert!(matches!(from_u32, FirmwareError::KnownSevError(_)));
        let from_u32: FirmwareError = 0x28u32.into();
        assert!(matches!(from_u32, FirmwareError::UnknownSevError(_)));
        let from_u64: FirmwareError = 0x1u64.into();
        assert!(matches!(from_u64, FirmwareError::KnownSevError(_)));
    }

    #[test]
    fn test_firmware_error_conversions() {
        // Test From<SevError>
        let sev_err = SevError::InvalidPlatformState;
        let fw_err = FirmwareError::from(sev_err);
        assert!(matches!(
            fw_err,
            FirmwareError::KnownSevError(SevError::InvalidPlatformState)
        ));

        let unknown_sev = SevError::UnknownError;
        let fw_err = FirmwareError::from(unknown_sev);
        assert!(matches!(fw_err, FirmwareError::UnknownSevError(_)));

        // Test From<io::Error>
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let fw_err = FirmwareError::from(io_err);
        assert!(matches!(fw_err, FirmwareError::IoError(_)));
    }

    #[test]
    fn test_user_api_error_complete() {
        let variants = vec![
            FirmwareError::UnknownSevError(0).into(),
            std::io::Error::new(std::io::ErrorKind::Other, "test").into(),
            CertError::UnknownError.into(),
            VmmError::Unknown.into(),
            uuid::Uuid::try_from("").unwrap_err().into(),
            HashstickError::UnknownError.into(),
            UserApiError::VmplError, // No From impl
            UserApiError::Unknown,   // No From impl
        ];

        for err in variants {
            // Test display
            assert!(!err.to_string().is_empty());
            // Test error source
            match &err {
                UserApiError::VmplError | UserApiError::Unknown => assert!(err.source().is_none()),
                _ => assert!(err.source().is_some()),
            }
            // Test io::Error conversion
            let _: std::io::Error = err.into();
        }

        let sev_error: SevError = SevError::InvalidPlatformState;
        let uapi_error: UserApiError = sev_error.into();
        assert!(matches!(uapi_error, UserApiError::FirmwareError(_)));
    }

    #[test]
    fn test_hashstick_error_complete() {
        let variants = vec![
            HashstickError::InvalidLength,
            HashstickError::EmptyHashstickBuffer,
            HashstickError::UnknownError,
        ];

        for err in variants {
            assert!(!err.to_string().is_empty());
            assert!(std::error::Error::source(&err).is_none());
        }
    }

    #[test]
    fn test_cert_error_complete() {
        let variants = vec![
            CertError::InvalidGUID,
            CertError::PageMisalignment,
            CertError::BufferOverflow,
            CertError::EmptyCertBuffer,
            CertError::UnknownError,
        ];

        for err in variants {
            assert!(!err.to_string().is_empty());
            assert!(std::error::Error::source(&err).is_none());
        }
    }

    #[test]
    fn test_gctx_error_complete() {
        let variants = vec![
            GCTXError::InvalidPageSize(100, 200),
            GCTXError::InvalidBlockSize,
            GCTXError::MissingData,
            GCTXError::MissingBlockSize,
            GCTXError::UnknownError,
        ];

        for err in variants {
            assert!(!err.to_string().is_empty());
            assert!(std::error::Error::source(&err).is_none());
        }
    }

    #[test]
    fn test_ovmf_error_complete() {
        let variants = vec![
            OVMFError::InvalidSectionType,
            OVMFError::SEVMetadataVerification("test".into()),
            OVMFError::EntryMissingInTable("test".into()),
            OVMFError::GetTableItemError,
            OVMFError::InvalidSize("test".into(), 1, 2),
            OVMFError::MismatchingGUID,
            OVMFError::UnknownError,
        ];

        for err in variants {
            assert!(!err.to_string().is_empty());
            assert!(std::error::Error::source(&err).is_none());
        }
    }

    #[test]
    fn test_sev_hash_error_complete() {
        let variants = vec![
            SevHashError::InvalidSize(1, 2),
            SevHashError::InvalidOffset(1, 2),
            SevHashError::UnknownError,
        ];

        for err in variants {
            assert!(!err.to_string().is_empty());
            assert!(std::error::Error::source(&err).is_none());
        }
    }

    #[test]
    fn test_large_array_error_complete() {
        let slice_err: Result<[u8; 2], TryFromSliceError> = vec![1u8].as_slice().try_into();
        let variants = vec![
            slice_err.unwrap_err().into(),
            ArrayError::VectorError("test".into()),
        ];

        for err in variants {
            assert!(!err.to_string().is_empty());
            assert!(std::error::Error::source(&err).is_none());
        }
    }

    #[test]
    fn test_id_block_error_complete() {
        let slice_err: Result<[u8; 2], TryFromSliceError> = vec![1u8].as_slice().try_into();
        let bincode_err: ErrorKind = bincode::ErrorKind::Custom("test".into());

        let variants = vec![
            ArrayError::VectorError("test".into()).into(),
            std::io::Error::new(std::io::ErrorKind::Other, "test").into(),
            bincode_err.into(),
            slice_err.unwrap_err().into(),
            IdBlockError::SevCurveError(),
            IdBlockError::SevEcsdsaSigError("test".into()),
        ];

        for err in variants {
            assert!(!err.to_string().is_empty());
            assert!(std::error::Error::source(&err).is_none());
        }

        // Test conversions
        let arr_err = ArrayError::VectorError("test".into());
        assert!(matches!(
            IdBlockError::from(arr_err),
            IdBlockError::LargeArrayError(_)
        ));
    }

    #[test]
    fn test_measurement_error_complete() {
        let slice_err: Result<[u8; 2], TryFromSliceError> = vec![1u8].as_slice().try_into();
        let bincode_err: ErrorKind = bincode::ErrorKind::Custom("test".into());

        let uuid_err = uuid::Uuid::try_from("").unwrap_err();

        let variants = vec![
            slice_err.unwrap_err().into(),
            uuid_err.into(),
            bincode_err.into(),
            std::io::Error::new(std::io::ErrorKind::Other, "test").into(),
            hex::FromHexError::OddLength.into(),
            GCTXError::UnknownError.into(),
            OVMFError::UnknownError.into(),
            SevHashError::UnknownError.into(),
            IdBlockError::SevCurveError().into(),
            ArrayError::VectorError("test".into()).into(),
            MeasurementError::InvalidVcpuTypeError("test".into()),
            MeasurementError::InvalidVcpuSignatureError("test".into()),
            MeasurementError::InvalidVmmError("test".into()),
            MeasurementError::InvalidSevModeError("test".into()),
            MeasurementError::InvalidOvmfKernelError,
            MeasurementError::MissingSection("test".into()),
        ];

        for err in variants {
            assert!(!err.to_string().is_empty());
            assert!(
                err.source().is_some()
                    || matches!(
                        err,
                        MeasurementError::FromSliceError(_)
                            | MeasurementError::UUIDError(_)
                            | MeasurementError::BincodeError(_)
                            | MeasurementError::FileError(_)
                            | MeasurementError::FromHexError(_)
                            | MeasurementError::GCTXError(_)
                            | MeasurementError::OVMFError(_)
                            | MeasurementError::SevHashError(_)
                            | MeasurementError::IdBlockError(_)
                            | MeasurementError::LargeArrayError(_)
                            | MeasurementError::InvalidVcpuTypeError(_)
                            | MeasurementError::InvalidVcpuSignatureError(_)
                            | MeasurementError::InvalidVmmError(_)
                            | MeasurementError::InvalidSevModeError(_)
                            | MeasurementError::InvalidOvmfKernelError
                            | MeasurementError::MissingSection(_)
                    )
            );
        }
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn test_openssl_features_complete() {
        // Test CertFormatError
        let cert_err = CertFormatError::UnknownFormat;
        assert!(!cert_err.to_string().is_empty());
        assert!(std::error::Error::source(&cert_err).is_none());

        // Test SessionError
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let variants = vec![
            SessionError::RandError(ErrorCode::HardwareFailure),
            SessionError::IOError(io_err),
            SessionError::OpenSSLStack(ErrorStack::get()),
        ];

        for err in variants {
            let debug_str = format!("{:?}", err);
            match err {
                SessionError::RandError(_) => assert!(debug_str.contains("RandError")),
                SessionError::IOError(_) => assert!(debug_str.contains("IOError")),
                SessionError::OpenSSLStack(_) => assert!(debug_str.contains("OpenSSLStack")),
            }
        }

        // Test conversions
        let from_io = SessionError::from(std::io::Error::new(std::io::ErrorKind::Other, "test"));
        assert!(matches!(from_io, SessionError::IOError(_)));

        let from_code = SessionError::from(ErrorCode::HardwareFailure);
        assert!(matches!(from_code, SessionError::RandError(_)));

        let from_stack = SessionError::from(ErrorStack::get());
        assert!(matches!(from_stack, SessionError::OpenSSLStack(_)));
    }
}
