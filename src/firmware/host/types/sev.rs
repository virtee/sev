// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

use std::fmt::Debug;

use crate::{firmware::host::State, Build};

#[cfg(target_os = "linux")]
pub use crate::firmware::host::Firmware;
pub use crate::firmware::linux::host::types::PlatformStatusFlags;

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
