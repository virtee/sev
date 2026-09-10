// SPDX-License-Identifier: Apache-2.0

//! Attester: collect attestation evidence from a guest VM.
//!
//! SNP guest attestation is in [`snp`](self::snp) ([`Firmware`](snp::Firmware)
//! on Linux). Enable the `attester` and `snp` features.

#[cfg(all(target_os = "linux", feature = "snp"))]
pub mod snp;
