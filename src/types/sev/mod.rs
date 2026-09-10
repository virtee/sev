// SPDX-License-Identifier: Apache-2.0

//! First-generation SEV ABI value types.
//!
//! Platform lifecycle and status types for legacy SEV hosts. Requires the
//! `sev` feature alongside `platform` for host API usage.
//!
//! For SNP platform equivalents see [`crate::types::snp::platform`].
//!
//! # Modules
//!
//! | Module | Types |
//! |--------|-------|
//! | [`platform`](self::platform) | [`State`] — platform lifecycle |
//! | [`status`](self::status) | [`Status`], [`Version`], [`PlatformStatusFlags`] |
//!
//! # Usage
//!
//! [`Status`] is returned by the shared
//! [`Firmware::platform_status`](crate::platform::Firmware::platform_status)
//! ioctl on both legacy SEV and SNP hosts (legacy layout).

mod platform;
mod status;

pub use platform::State;
pub use status::{PlatformStatusFlags, Status, Version};
