// SPDX-License-Identifier: Apache-2.0

/// Legacy SEV certificates.
#[cfg(feature = "sev")]
pub mod sev;

/// SEV-SNP certificates.
#[cfg(feature = "snp")]
pub mod snp;
