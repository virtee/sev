// SPDX-License-Identifier: Apache-2.0

/// Legacy SEV certificates.
#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
#[cfg(feature = "sev")]
pub mod sev;

/// SEV-SNP certificates.
#[cfg(feature = "snp")]
pub mod snp;
