// SPDX-License-Identifier: Apache-2.0

//! Everything one needs to launch an AMD SEV encrypted virtual machine.
//!
//! This module contains types for establishing a secure channel with the
//! AMD Secure Processor for purposes of attestation as well as abstractions
//! for navigating the AMD SEV launch process for a virtual machine.
//!
//! # Features
//!
//! | Submodule | Required features |
//! |-----------|-------------------|
//! | [`snp`](self::snp) | `launch` + `snp` (Linux) |
//! | [`sev`](self::sev) | `launch` + `sev` + `verifier` (Linux; `verifier` implies `endorser`) |
//!
//! All launch flows initialize KVM through the `KVM_SEV_INIT2` ioctl.

#[cfg(all(any(feature = "sev", feature = "snp"), target_os = "linux"))]
mod linux;

#[cfg(all(
    feature = "sev",
    feature = "endorser",
    feature = "verifier",
    target_os = "linux"
))]
pub mod sev;

#[cfg(all(feature = "snp", target_os = "linux"))]
pub mod snp;
