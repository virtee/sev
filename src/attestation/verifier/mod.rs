// SPDX-License-Identifier: Apache-2.0

//! RATS Verifier role: appraise attestation evidence and endorsements.
//!
//! This module implements the **Verifier** role in the RATS architecture. It
//! validates cryptographic relationships between endorsement material and
//! attestation evidence so callers can treat parsed report fields as authentic.
//!
//! Evidence types live in [`crate::attestation::evidence`]; endorsement
//! material is parsed in [`crate::attestation::endorser`]. The verifier connects
//! the two through [`Verifiable`] implementations.
//!
//! # Platform modules
//!
//! | Module | Scope |
//! |--------|-------|
//! | [`snp`](self::snp) | SEV-SNP certificate chains and attestation reports (default) |
//! | [`sev`](self::sev) | Legacy first-generation SEV (requires `sev` feature) |
//!
//! # Core API
//!
//! All verification entry points implement [`Verifiable`]. Call `.verify()` on
//! the appropriate input tuple or reference — for example
//! `(&Chain, &Report).verify()` for SNP — rather than calling submodule
//! functions directly.
//!
//! Successful verification returns [`Verifiable::Output`], which may be `()` or
//! a trusted reference (such as a validated VCEK certificate). Failures are
//! reported as [`std::io::Error`].
//!
//! # Typical SNP workflow
//!
//! ```ignore
//! use sev::attestation::{
//!     evidence::snp::{Report, ReportBody},
//!     endorser::snp::Chain,
//!     verifier::Verifiable,
//! };
//!
//! let chain = Chain::from_pem(&pem_bytes)?;
//! let report = Report::from_bytes(&raw_report)?;
//!
//! (chain, &report).verify()?;
//! let body = ReportBody::try_from((&report, &chain))?;
//! ```
//!
//! See [`snp`](self::snp) for the full verification layer table and
//! [`Verifiable`] for the trait contract.
//!
//! # Features
//!
//! Requires the `verifier` feature (which pulls in `evidence` and `endorser`),
//! plus either `snp` or `sev`, and a crypto backend (`crypto-openssl` or
//! `crypto-rust` for SNP).

mod verifiable;

#[cfg(all(
    feature = "snp",
    any(feature = "crypto-openssl", feature = "crypto-rust")
))]
pub mod snp;

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
pub mod sev;

pub use verifiable::Verifiable;
