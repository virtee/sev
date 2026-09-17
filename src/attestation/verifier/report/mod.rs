// SPDX-License-Identifier: Apache-2.0

//! Attestation report framing and parsing.
//!
//! Report types are part of the verifier surface: they decode untrusted wire
//! bytes before signature and chain appraisal in [`crate::attestation::verifier`].
//!
//! - [`snp`](self::snp) — SEV-SNP attestation reports (`feature = "snp"`)
//! - [`sev`](self::sev) — legacy SEV reports (`feature = "sev"`)

#[cfg(feature = "snp")]
pub mod snp;

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
pub mod sev;
