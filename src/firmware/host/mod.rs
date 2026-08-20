// SPDX-License-Identifier: Apache-2.0

//! Host `/dev/sev` ioctl argument layouts.
//!
//! C-compatible structs and ioctl constants for the Linux PSP/SEV host device.
//! Public platform APIs are in [`crate::platform::Firmware`], which issues
//! these ioctls on behalf of the caller.
//!
//! # Submodules
//!
//! | Module | Scope |
//! |--------|-------|
//! | [`types`](self::types) | Request/response payload layouts ([`shared`](self::types::shared), [`sev`](self::types::sev), [`snp`](self::types::snp)) |
//! | [`ioctl`](self::ioctl) | Ioctl numbers and [`Command`] envelope |

#[cfg(feature = "platform")]
pub(crate) mod types;

#[cfg(all(target_os = "linux", feature = "platform"))]
pub(crate) mod ioctl;
