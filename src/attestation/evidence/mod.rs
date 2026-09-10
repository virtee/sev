// SPDX-License-Identifier: Apache-2.0

//! Attestation evidence framing and parsing (RATS Evidence role).
//!
//! - [`snp`](self::snp) — SEV-SNP attestation reports (`feature = "snp"`)
//! - [`sev`](self::sev) — legacy SEV reports (`feature = "sev"`)

#[cfg(feature = "snp")]
pub mod snp;

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
pub mod sev;
