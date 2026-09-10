// SPDX-License-Identifier: Apache-2.0

//! SEV-SNP host platform management.
//!
//! Extends [`crate::platform::Firmware`] with SNP-specific ioctls: platform
//! status, TCB commit, system configuration, and VLEK hashstick loading.
//! Wire types are re-exported from [`crate::types::snp::platform`].
//!
//! Requires the `snp` and `platform` features.
//!
//! # Generation parameter
//!
//! SNP platform status and configuration ioctls return or accept TCB bytes
//! whose field layout varies by EPYC generation (Milan vs Turin, etc.). Every
//! method that decodes or encodes TCB data requires an explicit
//! [`Generation`](crate::types::shared::Generation). The library
//! does not call [`crate::firmware::cpuid::identify_host_generation`] automatically.
//!
//! # API summary
//!
//! | Method | Purpose |
//! |--------|---------|
//! | [`Firmware::snp_platform_status`] | Query SNP platform status and TCB versions |
//! | [`Firmware::snp_commit`] | Commit current firmware TCB/version to the platform |
//! | [`Firmware::snp_set_config`] | Set reported TCB and chip-ID mask |
//! | [`Firmware::snp_vlek_load`] | Load a VLEK hashstick for VLEK-based attestation |
//!
//! Shared ioctls ([`Firmware::get_identifier`], [`Firmware::platform_status`])
//! are on the base [`crate::platform::Firmware`] impl in [`super`].
//!
//! # Typical workflow
//!
//! ```ignore
//! use sev::platform::Firmware;
//! use sev::types::shared::Generation;
//! use sev::types::snp::platform::Config;
//!
//! let mut fw = Firmware::open()?;
//! let generation = Generation::Turin;
//!
//! let status = fw.snp_platform_status(generation)?;
//! fw.snp_set_config(Config::new(reported_tcb, mask_id), generation)?;
//! fw.snp_commit()?;
//! ```

pub use crate::types::snp::platform::*;

#[cfg(target_os = "linux")]
use super::Firmware;

#[cfg(target_os = "linux")]
use crate::error::*;

#[cfg(target_os = "linux")]
use crate::firmware::host::{
    ioctl::*,
    types::{
        SnpCommit, SnpPlatformStatus as FFISnpPlatformStatus, SnpSetConfig, SnpVlekLoad,
        WrappedVlekHashstick as FFIWrappedVlekHashstick,
    },
};

#[cfg(target_os = "linux")]
use crate::parser::ByteParser;

#[cfg(target_os = "linux")]
use crate::types::shared::Generation;

#[cfg(target_os = "linux")]
use std::convert::{TryFrom, TryInto};

#[cfg(target_os = "linux")]
impl TryFrom<(Config, Generation)> for SnpSetConfig {
    type Error = std::io::Error;

    fn try_from(args: (Config, Generation)) -> Result<Self, Self::Error> {
        let (value, generation) = args;
        Ok(SnpSetConfig::new(
            value.reported_tcb.to_bytes_with(generation)?,
            value.mask_id,
        ))
    }
}

#[cfg(target_os = "linux")]
impl TryFrom<(SnpSetConfig, Generation)> for Config {
    type Error = std::io::Error;

    fn try_from(value: (SnpSetConfig, Generation)) -> Result<Self, Self::Error> {
        let (config, generation) = value;
        Ok(Config::new(
            crate::types::snp::TcbVersion::from_bytes_with(&config.reported_tcb, generation)?,
            config.mask_id,
        ))
    }
}

#[cfg(target_os = "linux")]
impl Firmware {
    /// Query SNP platform status and capabilities.
    ///
    /// Decodes the 32-byte firmware response into [`SnpPlatformStatus`] using
    /// `generation` to select the correct TCB field layout.
    ///
    /// # Errors
    ///
    /// Returns [`UserApiError`](crate::error::UserApiError) on ioctl failure or
    /// [`std::io::Error`] if the response bytes cannot be decoded for the given
    /// generation.
    pub fn snp_platform_status(
        &mut self,
        generation: Generation,
    ) -> Result<SnpPlatformStatus, UserApiError> {
        let mut platform_status: FFISnpPlatformStatus = FFISnpPlatformStatus::default();

        let mut cmd_buf = Command::from_mut(&mut platform_status);

        SNP_PLATFORM_STATUS
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(SnpPlatformStatus::from_bytes_with(
            &platform_status.buffer,
            generation,
        )?)
    }

    /// Commit the current firmware TCB and version to the platform.
    ///
    /// The firmware will:
    /// - set `CommittedTCB` to the current firmware TCB
    /// - set `CommittedVersion` to the current firmware version
    /// - set `ReportedTCB` to the current TCB
    /// - delete the loaded VLEK hashstick if `ReportedTCB` changed
    pub fn snp_commit(&mut self) -> Result<(), UserApiError> {
        let mut buf: SnpCommit = Default::default();
        let mut cmd_buf = Command::from_mut(&mut buf);

        SNP_COMMIT
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(())
    }

    /// Apply SNP platform configuration.
    ///
    /// Sets the reported TCB version (embedded in attestation reports) and the
    /// chip-ID mask. Encodes `new_config` using `generation` for TCB layout.
    pub fn snp_set_config(
        &mut self,
        new_config: Config,
        generation: Generation,
    ) -> Result<(), UserApiError> {
        let mut binding: SnpSetConfig = (new_config, generation).try_into()?;

        let mut cmd_buf = Command::from_mut(&mut binding);

        SNP_SET_CONFIG
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(())
    }

    /// Load a Versioned Loaded Endorsement Key (VLEK) hashstick.
    ///
    /// Enables VLEK-based attestation in place of per-chip VCEK. The hashstick
    /// must conform to the wrapped format validated by
    /// [`WrappedVlekHashstick`](crate::types::snp::platform::WrappedVlekHashstick)
    /// (SNP firmware specification chapter 8.30).
    pub fn snp_vlek_load(
        &mut self,
        hashstick: WrappedVlekHashstick,
        generation: Generation,
    ) -> Result<(), UserApiError> {
        let buffer = hashstick.to_bytes_with(generation)?;

        let parsed_bytes: FFIWrappedVlekHashstick =
            FFIWrappedVlekHashstick::try_from(buffer.as_slice())?;

        let mut vlek_load: SnpVlekLoad = SnpVlekLoad::new(&parsed_bytes);
        let mut cmd_buf = Command::from_mut(&mut vlek_load);

        SNP_VLEK_LOAD
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(())
    }
}
