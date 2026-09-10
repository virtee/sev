// SPDX-License-Identifier: Apache-2.0

//! First-generation SEV platform status and version types.
//!
//! Populated by [`crate::platform::Firmware::platform_status`] when the `platform`
//! and `sev` features are enabled. For the SNP equivalents see
//! [`crate::types::snp::platform`].

use super::State;
use crate::types::shared::FirmwareVersion;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    /// The platform's status flags.
    #[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PlatformStatusFlags: u32 {
        /// If set, this platform is owned. Otherwise, it is self-owned.
        const OWNED           = 1 << 0;

        /// If set, encrypted state functionality is present.
        const ENCRYPTED_STATE = 1 << 8;
    }
}

/// Information about the SEV platform version (major/minor only).
///
/// Used in ioctl layouts and certificate bodies where the build number is
/// stored separately. For the full major/minor/build triple, use
/// [`FirmwareVersion`](crate::types::shared::FirmwareVersion).
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// The major version number.
    pub major: u8,

    /// The minor version number.
    pub minor: u8,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl From<u16> for Version {
    fn from(v: u16) -> Self {
        Self {
            major: ((v & 0xF0) >> 4) as u8,
            minor: (v & 0x0F) as u8,
        }
    }
}

impl From<(Version, u8)> for FirmwareVersion {
    fn from((version, build): (Version, u8)) -> Self {
        Self::new(version.major, version.minor, build)
    }
}

/// High-level SEV platform status returned by [`crate::platform::Firmware::platform_status`].
///
/// Combines firmware version, lifecycle [`State`], ownership/encrypted-state
/// [`PlatformStatusFlags`], and the number of active guests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The firmware version (major, minor, build).
    pub firmware_version: FirmwareVersion,

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
