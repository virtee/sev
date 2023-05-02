// SPDX-License-Identifier: Apache-2.0

//! Everything one needs to launch an AMD SEV encrypted virtual machine.
//!
//! This module contains types for establishing a secure channel with the
//! AMD Secure Processor for purposes of attestation as well as abstractions
//! for navigating the AMD SEV launch process for a virtual machine.

#[cfg(target_os = "linux")]
#[cfg(any(feature = "sev", feature = "snp"))]
mod linux;

#[cfg(feature = "sev")]
pub mod sev;

#[cfg(feature = "snp")]
pub mod snp;
