// SPDX-License-Identifier: Apache-2.0

//! Host `/dev/sev` ioctl payload layouts.
//!
//! C-compatible structs passed to the Linux kernel for platform management
//! ioctls. Layouts are split by scope:
//!
//! | Module | Scope |
//! |--------|-------|
//! | [`shared`](self::shared) | Legacy SEV **and** SEV-SNP (`PLATFORM_STATUS`, `GET_ID`) |
//! | [`sev`](self::sev) | Legacy SEV only (`sev` feature) |
//! | [`snp`](self::snp) | SEV-SNP only (`snp` feature) |
//!
//! Decoded status values are returned by [`crate::platform::Firmware`] methods
//! using the corresponding types in [`crate::types`].

#[cfg(feature = "platform")]
mod shared;

#[cfg(all(feature = "sev", feature = "platform", feature = "endorser"))]
mod sev;

#[cfg(all(feature = "snp", feature = "platform"))]
mod snp;

#[cfg(feature = "platform")]
pub use self::shared::*;

#[cfg(all(feature = "sev", feature = "platform", feature = "endorser"))]
pub use self::sev::*;

#[cfg(all(feature = "snp", feature = "platform"))]
pub use self::snp::*;
