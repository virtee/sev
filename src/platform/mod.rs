// SPDX-License-Identifier: Apache-2.0

//! Host platform management for AMD SEV and SEV-SNP.
//!
//! Opens `/dev/sev` and exposes host-side platform ioctls: status queries,
//! configuration, and (for legacy SEV) certificate provisioning. This is the
//! **host** counterpart to guest attestation in
//! [`crate::attestation::attester::snp::Firmware`] (`/dev/sev-guest`).
//!
//! Low-level ioctl layouts live in [`crate::firmware::host`]. Decoded wire
//! types live in [`crate::types`]. This module wraps both into typed Rust APIs.
//!
//! # API layers
//!
//! ```text
//!  /dev/sev
//!      │
//!  platform::Firmware::open()
//!      │
//!      ├─ Shared (legacy SEV + SNP)
//!      │     get_identifier()      ──► Identifier
//!      │     platform_status()     ──► Status
//!      │
//!      ├─ Legacy SEV only [`sev`](self::sev)
//!      │     pek_generate / pek_csr / pek_cert_import
//!      │     pdh_generate / pdh_cert_export
//!      │     platform_reset
//!      │
//!      └─ SEV-SNP only [`snp`](self::snp)
//!            snp_platform_status / snp_commit
//!            snp_set_config / snp_vlek_load
//! ```
//!
//! # Features
//!
//! | API | Required features |
//! |-----|---------------------|
//! | [`Firmware::open`] | `platform` (Linux) |
//! | Shared methods | `platform` + (`sev` or `snp`) |
//! | [`sev`](self::sev) methods | `platform` + `sev` + `endorser` + `verifier` |
//! | [`snp`](self::snp) methods | `platform` + `snp` |
//!
//! SNP platform ioctls that decode TCB fields require an explicit
//! [`Generation`](crate::types::shared::Generation) — the library
//! does not auto-detect the host CPU generation.
//!
//! # Typical SNP workflow
//!
//! ```ignore
//! use sev::platform::Firmware;
//! use sev::types::shared::Generation;
//!
//! let mut fw = Firmware::open()?;
//! let id = fw.get_identifier()?;
//! let status = fw.snp_platform_status(Generation::Turin)?;
//! fw.snp_commit()?;
//! ```
//!
//! # Errors
//!
//! Ioctl failures map to [`UserApiError`](crate::error::UserApiError), wrapping
//! [`FirmwareError`](crate::error::FirmwareError) from the PSP firmware status
//! word returned by the kernel.

#[cfg(all(feature = "sev", feature = "endorser", feature = "verifier"))]
pub mod sev;

#[cfg(feature = "snp")]
pub mod snp;

#[cfg(target_os = "linux")]
use crate::firmware::host::{ioctl::*, types::GetId};

#[cfg(all(target_os = "linux", any(feature = "sev", feature = "snp")))]
use crate::firmware::host::types::PlatformStatus;

#[cfg(all(target_os = "linux", any(feature = "sev", feature = "snp")))]
use crate::types::shared::FirmwareVersion;

#[cfg(any(feature = "sev", feature = "snp"))]
pub use crate::types::sev::{State, Status, Version};

#[cfg(target_os = "linux")]
use crate::error::*;

#[cfg(target_os = "linux")]
use std::{
    fs::{File, OpenOptions},
    os::unix::io::{AsRawFd, RawFd},
};

/// CPU-unique platform identifier returned by [`Firmware::get_identifier`].
///
/// Hex-formatted via [`Display`](std::fmt::Display). Used to request signed
/// CEK/VCEK certificates from AMD's key server.
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

/// Handle to the host SEV platform device (`/dev/sev`).
///
/// Shared entry point for both legacy SEV and SEV-SNP host management. Open
/// with [`Self::open`], then call methods from this module or the [`sev`](self::sev)
/// / [`snp`](self::snp) extension impls.
///
/// # Platform requirements
///
/// - Linux host with `/dev/sev` device node
/// - `platform` feature enabled
/// - Appropriate kernel/PSP driver support for the desired ioctls
#[cfg(target_os = "linux")]
pub struct Firmware(pub(crate) File);

#[cfg(target_os = "linux")]
impl Firmware {
    /// Open a read/write handle to `/dev/sev`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the device node is missing or cannot be
    /// opened (for example, the PSP driver is not loaded or the user lacks permission).
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }

    /// Read the CPU unique identifier via the shared `GET_ID` ioctl.
    ///
    /// Available on both legacy SEV and SEV-SNP hosts. The identifier is
    /// typically used to fetch a signed CEK or VCEK certificate from AMD.
    ///
    /// # Errors
    ///
    /// Returns [`UserApiError::FirmwareError`](crate::error::UserApiError) when
    /// the PSP rejects the request.
    #[cfg(any(feature = "sev", feature = "snp"))]
    pub fn get_identifier(&mut self) -> Result<Identifier, UserApiError> {
        let mut bytes = [0u8; 64];
        let mut id = GetId::new(&mut bytes);
        let mut cmd_buf = Command::from_mut(&mut id);

        GET_ID
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(Identifier(id.as_slice().to_vec()))
    }

    /// Query legacy SEV platform status via the shared `PLATFORM_STATUS` ioctl.
    ///
    /// Available on both legacy SEV and SEV-SNP hosts. Returns firmware version,
    /// lifecycle [`State`], [`PlatformStatusFlags`](crate::types::sev::PlatformStatusFlags),
    /// and active guest count. For SNP-specific status fields, use
    /// [`snp_platform_status`](crate::platform::Firmware::snp_platform_status) instead.
    ///
    /// # Errors
    ///
    /// Returns [`UserApiError`] when the ioctl fails or the platform state byte
    /// is unrecognized.
    #[cfg(any(feature = "sev", feature = "snp"))]
    pub fn platform_status(&mut self) -> Result<Status, UserApiError> {
        let mut info: PlatformStatus = Default::default();
        let mut cmd_buf = Command::from_mut(&mut info);
        PLATFORM_STATUS
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(Status {
            firmware_version: FirmwareVersion::new(
                info.version.major,
                info.version.minor,
                info.build,
            ),
            guests: info.guest_count,
            flags: info.flags,
            state: match info.state {
                0 => State::Uninitialized,
                1 => State::Initialized,
                2 => State::Working,
                _ => return Err(SevError::InvalidPlatformState)?,
            },
        })
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
