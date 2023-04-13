// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

#[cfg(target_os = "linux")]
use super::*;

use std::{error, fmt::Debug, io};

bitflags::bitflags! {
    /// The platform's status flags.
    #[derive(Default)]
    pub struct PlatformStatusFlags: u32 {
        /// If set, this platform is owned. Otherwise, it is self-owned.
        const OWNED           = 1 << 0;

        /// If set, encrypted state functionality is present.
        const ENCRYPTED_STATE = 1 << 8;
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
    /// Creates a new isntance of a TcbVersion
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

    /// Uuid parsing errors.
    UuidError(uuid::Error),
}

impl error::Error for UserApiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            UserApiError::FirmwareError(firmware_error) => Some(firmware_error),
            UserApiError::UuidError(uuid_error) => Some(uuid_error),
        }
    }
}

impl std::fmt::Display for UserApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let err_msg: String = match self {
            UserApiError::FirmwareError(error) => format!("Firmware Error Encountered: {error}"),
            UserApiError::UuidError(error) => format!("UUID Error Encountered: {error}"),
        };
        write!(f, "{err_msg}")
    }
}

impl std::convert::From<uuid::Error> for UserApiError {
    fn from(uuid_error: uuid::Error) -> Self {
        UserApiError::UuidError(uuid_error)
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

impl error::Error for Indeterminate<Error> {}

impl std::fmt::Display for Indeterminate<Error> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_description = match self {
            Indeterminate::Known(error) => format!("Known Error: {error}"),
            Indeterminate::Unknown => "Unknown Error Encountered".to_string(),
        };

        write!(f, "{err_description}")
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
