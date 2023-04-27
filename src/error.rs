// SPDX-License-Identifier: Apache-2.0

use std::{
    convert::From,
    error,
    fmt::{Debug, Display},
    io,
};

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
    /// Takes a raw u32 and translates it into the correlated [`VmmError`]
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
    /// Takes a raw u64 and translates it into the correlated [`VmmError`]
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
pub(crate) struct RawFwError(u64);

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

impl From<RawFwError> for (VmmError, Indeterminate<Error>) {
    fn from(value: RawFwError) -> Self {
        ((value.0 >> 0x20).into(), value.0.into())
    }
}

impl Display for RawFwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawFwError: {}", self.0)
    }
}

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
    ApiError(CertError),

    /// Errors returned by the VMM via ioctl().
    VmmError(VmmError),

    /// Uuid parsing errors.
    UuidError(uuid::Error),

    /// Invalid VMPL.
    VmplError,

    /// Unknown error
    Unknown,
}

impl error::Error for UserApiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::ApiError(uapi_error) => Some(uapi_error),
            Self::FirmwareError(firmware_error) => Some(firmware_error),
            Self::UuidError(uuid_error) => Some(uuid_error),
            Self::VmmError(vmm_error) => Some(vmm_error),
            Self::VmplError => None,
            Self::Unknown => None,
        }
    }
}

impl std::fmt::Display for UserApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let err_msg: String = match self {
            Self::FirmwareError(error) => format!("Firmware Error Encountered: {error}"),
            Self::ApiError(error) => format!("Certificate Error Encountered: {error}"),
            Self::UuidError(error) => format!("UUID Error Encountered: {error}"),
            Self::VmmError(error) => format!("VMM Error Encountered: {error}"),
            Self::VmplError => "Invalid VM Permission Level (VMPL)".to_string(),
            Self::Unknown => "Unknown Error Encountered!".to_string(),
        };
        write!(f, "{err_msg}")
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

impl std::convert::From<Error> for UserApiError {
    fn from(firmware_error: Error) -> Self {
        Self::FirmwareError(firmware_error)
    }
}

impl std::convert::From<std::io::Error> for UserApiError {
    fn from(io_error: std::io::Error) -> Self {
        Self::FirmwareError(Error::IoError(io_error))
    }
}

impl std::convert::From<CertError> for UserApiError {
    fn from(cert_error: CertError) -> Self {
        Self::ApiError(cert_error)
    }
}

#[derive(Debug)]
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

/// Error conditions returned by the SEV platform or by layers above it
/// (i.e., the Linux kernel).
///
/// These error conditions are documented in the AMD SEV API spec, but
/// their documentation has been copied here for completeness.
#[derive(Debug)]
#[repr(u32)]
pub enum Error {
    /// Something went wrong when communicating with the "outside world"
    /// (kernel, SEV platform).
    IoError(io::Error),

    /// The platform state is invalid for this command.
    InvalidPlatformState, // 0x0001

    /// The guest state is invalid for this command.
    InvalidGuestState, // 0x0002

    /// The platform configuration is invalid.
    InvalidConfig, // 0x0003

    /// A memory buffer is too small.
    InvalidLen, // 0x0004

    /// The platform is already owned.
    AlreadyOwned, // 0x0005

    /// The certificate is invalid.
    InvalidCertificate, // 0x0006

    /// Request is not allowed by guest policy.
    PolicyFailure, // 0x0007

    /// The guest is inactive.
    Inactive, // 0x0008

    /// The address provided is invalid.
    InvalidAddress, // 0x0009

    /// The provided signature is invalid.
    BadSignature, // 0x000A

    /// The provided measurement is invalid.
    BadMeasurement, // 0x000B

    /// The ASID is already owned.
    AsidOwned, // 0x000C

    /// The ASID is invalid.
    InvalidAsid, // 0x000D

    /// WBINVD instruction required.
    WbinvdRequired, // 0x000E

    /// `DF_FLUSH` invocation required.
    DfFlushRequired, // 0x000F

    /// The guest handle is invalid.
    InvalidGuest, // 0x0010

    /// The command issued is invalid.
    InvalidCommand, // 0x0011

    /// The guest is active.
    Active, // 0x0012

    /// A hardware condition has occurred affecting the platform. It is safe
    /// to re-allocate parameter buffers.
    HardwarePlatform, // 0x0013

    /// A hardware condition has occurred affecting the platform. Re-allocating
    /// parameter buffers is not safe.
    HardwareUnsafe, // 0x0014

    /// Feature is unsupported.
    Unsupported, // 0x0015

    /// A given parameter is invalid.
    InvalidParam, // 0x0016

    /// The SEV firmware has run out of a resource required to carry out the
    /// command.
    ResourceLimit, // 0x0017

    /// The SEV platform observed a failed integrity check.
    SecureDataInvalid, // 0x0018

    /// The RMP page size is incorrect.
    InvalidPageSize, // 0x0019

    /// The RMP page state is incorrect
    InvalidPageState, // 0x001A

    /// The metadata entry is invalid.
    InvalidMdataEntry, // 0x001B

    /// The page ownership is incorrect
    InvalidPageOwner, // 0x001C

    /// The AEAD algorithm would have overflowed
    AEADOFlow, // 0x001D

    /// A Mailbox mode command was sent while the SEV FW was in Ring Buffer
    /// mode. Ring Buffer mode has been exited; the Mailbox mode command
    /// has been ignored. Retry is recommended.
    RbModeExited = 0x001F, // 0x001F

    /// The RMP must be reinitialized.
    RMPInitRequired = 0x0020, // 0x0020

    /// SVN of provided image is lower than the committed SVN.
    BadSvn, // 0x0021

    /// Firmware version anti-rollback.
    BadVersion, // 0x0022

    /// An invocation of SNP_SHUTDOWN is required to complete this action.
    ShutdownRequired, // 0x0023

    /// Update of the firmware internal state or a guest context page has failed.
    UpdateFailed, // 0x0024

    /// Installation of the committed firmware image required
    RestoreRequired, // 0x0025

    /// The RMP initialization failed.
    RMPInitFailed, // 0x0026

    /// The key requested is invalid, not present, or not allowed.
    InvalidKey, // 0x0027
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
            Error::InvalidPageSize => "The RMP page size is incorrect.",
            Error::InvalidPageState => "The RMP page state is incorrect.",
            Error::InvalidMdataEntry => "The metadata entry is invalid.",
            Error::InvalidPageOwner => "The page ownership is incorrect",
            Error::AEADOFlow => "The AEAD algorithm would have overflowed.",
            Error::RbModeExited => "A Mailbox mode command was sent while the SEV FW was in Ring Buffer \
                                    mode. Ring Buffer mode has been exited; the Mailbox mode command has \
                                    been ignored. Retry is recommended.",
            Error::RMPInitRequired => "The RMP must be reinitialized.",
            Error::BadSvn => "SVN of provided image is lower than the committed SVN",
            Error::BadVersion => "Firmware version anti-rollback.",
            Error::ShutdownRequired => "An invocation of SNP_SHUTDOWN is required to complete this action.",
            Error::UpdateFailed => "Update of the firmware internal state or a guest context page has failed.",
            Error::RestoreRequired => "Installation of the committed firmware image required.",
            Error::RMPInitFailed => "The RMP initialization failed.",
            Error::InvalidKey => "The key requested is invalid, not present, or not allowed",
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

impl error::Error for Indeterminate<Error> {}

impl Display for Indeterminate<Error> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_description = match self {
            Indeterminate::Known(error) => format!("Known Error: {error}"),
            Indeterminate::Unknown => "Unknown Error Encountered".to_string(),
        };

        write!(f, "{err_description}")
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

impl From<u64> for Indeterminate<Error> {
    fn from(value: u64) -> Self {
        Self::from(value as u32)
    }
}

impl From<u32> for Indeterminate<Error> {
    #[inline]
    fn from(error: u32) -> Indeterminate<Error> {
        Indeterminate::Known(match error {
            0x00 => io::Error::last_os_error().into(),
            0x01 => Error::InvalidPlatformState,
            0x02 => Error::InvalidGuestState,
            0x03 => Error::InvalidConfig,
            0x04 => Error::InvalidLen,
            0x05 => Error::AlreadyOwned,
            0x06 => Error::InvalidCertificate,
            0x07 => Error::PolicyFailure,
            0x08 => Error::Inactive,
            0x09 => Error::InvalidAddress,
            0x0A => Error::BadSignature,
            0x0B => Error::BadMeasurement,
            0x0C => Error::AsidOwned,
            0x0D => Error::InvalidAsid,
            0x0E => Error::WbinvdRequired,
            0x0F => Error::DfFlushRequired,
            0x10 => Error::InvalidGuest,
            0x11 => Error::InvalidCommand,
            0x12 => Error::Active,
            0x13 => Error::HardwarePlatform,
            0x14 => Error::HardwareUnsafe,
            0x15 => Error::Unsupported,
            0x16 => Error::InvalidParam,
            0x17 => Error::ResourceLimit,
            0x18 => Error::SecureDataInvalid,
            0x19 => Error::InvalidPageSize,
            0x1A => Error::InvalidPageState,
            0x1B => Error::InvalidMdataEntry,
            0x1C => Error::InvalidPageOwner,
            0x1D => Error::AEADOFlow,
            0x1F => Error::RbModeExited,
            0x20 => Error::RMPInitRequired,
            0x21 => Error::BadSvn,
            0x22 => Error::BadVersion,
            0x23 => Error::ShutdownRequired,
            0x24 => Error::UpdateFailed,
            0x25 => Error::RestoreRequired,
            0x26 => Error::RMPInitFailed,
            0x27 => Error::InvalidKey,
            _ => return Indeterminate::Unknown,
        })
    }
}
