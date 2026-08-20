// SPDX-License-Identifier: Apache-2.0

//! Linux ioctl definitions for AMD SEV host and guest firmware devices.
//!
//! This module holds the low-level, kernel-facing ioctl layouts used by higher-level
//! APIs. It is `pub(crate)` — callers should use the public wrappers instead:
//!
//! | Sub-module | Device | Public API |
//! |------------|--------|------------|
//! | [`host`](self::host) | `/dev/sev` | [`crate::platform::Firmware`] |
//! | [`guest`](self::guest) | `/dev/sev-guest` | [`crate::attestation::attester::snp::Firmware`] |
//! | [`cpuid`](self::cpuid) | Host CPUID | Used by platform helpers (explicit `Generation` parameter) |
//!
//! # Architecture
//!
//! ```text
//!  Host (platform)                    Guest (attester)
//!  ───────────────                    ────────────────
//!  /dev/sev                           /dev/sev-guest
//!       │                                  │
//!  host::ioctl                          guest::ioctl
//!  host::types                          guest::types
//!       │                                  │
//!  platform::Firmware                 attester::snp::Firmware
//!  (status, config, certs)             (reports, derived keys)
//! ```
//!
//! Wire-format value types shared across ioctl boundaries live in
//! [`crate::types`]. This module contains only the C-layout structs and ioctl
//! constants expected by the Linux kernel UAPI.
//!
//! # Features
//!
//! | Sub-module | Required features |
//! |------------|-------------------|
//! | `host` | `platform` |
//! | `guest` | `attester` + `snp` (Linux only) |
//! | `cpuid` | `snp` (Linux x86_64 only) |

#[cfg(feature = "platform")]
pub(crate) mod host;

#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "snp"))]
pub(crate) mod cpuid;

#[cfg(all(feature = "attester", feature = "snp"))]
pub(crate) mod guest;

/// Standard 4 KiB page size used for guest certificate buffer alignment.
pub(crate) const _4K_PAGE: usize = 4096;
