// SPDX-License-Identifier: Apache-2.0

//! SNP platform configuration value types.
//!
//! Host-configurable values written via [`crate::platform::Firmware::snp_set_config`].
//! Currently exposes [`MaskId`] for chip-ID and VCEK masking in attestation reports.

mod mask;

pub use mask::MaskId;
