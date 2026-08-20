// SPDX-License-Identifier: Apache-2.0

//! Linux SNP guest firmware ioctl definitions.
//!
//! Low-level request/response structures and ioctl bindings for the
//! `/dev/sev-guest` device. The Linux kernel forwards these to the AMD Secure
//! Processor (ASP) on behalf of the guest VM.
//!
//! Public guest attestation APIs live in
//! [`crate::attestation::attester::snp::Firmware`], which wraps the ioctls
//! defined here.
//!
//! # Ioctl summary
//!
//! | Constant | Purpose |
//! |----------|---------|
//! | `SNP_GET_REPORT` | Standard 1184-byte attestation report |
//! | `SNP_GET_EXT_REPORT` | Report plus optional certificate table |
//! | `SNP_GET_DERIVED_KEY` | Guest-derived key (vCPU-secrets, etc.) |
//!
//! # Submodules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`ioctl`](self::ioctl) | Ioctl numbers and [`GuestRequest`] envelope |
//! | [`types`](self::types) | Request/response C layouts |
//! | [`cert_table`](self::cert_table) | Kernel certificate-table wire format |

#[cfg(target_os = "linux")]
pub(crate) mod cert_table;
#[cfg(target_os = "linux")]
pub(crate) mod ioctl;
#[cfg(target_os = "linux")]
pub(crate) mod types;
