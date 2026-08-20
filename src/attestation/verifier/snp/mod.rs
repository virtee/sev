// SPDX-License-Identifier: Apache-2.0

//! SNP attestation verification.
//!
//! This module implements the RATS **Verifier** role for SEV-SNP. It validates
//! AMD endorsement chains and attestation report signatures so callers can trust
//! evidence from [`crate::attestation::evidence::snp`].
//!
//! Endorsement material is parsed in [`crate::attestation::endorser::snp`]; this
//! module performs the cryptographic checks. All verification entry points
//! implement [`Verifiable`](crate::attestation::verifier::Verifiable).
//!
//! # Verification layers
//!
//! ```text
//!  ARK (self-signed)
//!    └── signs ──► ASK
//!                      └── signs ──► VCEK / VLEK
//!                                            └── signs ──► report body
//! ```
//!
//! | Layer | [`Verifiable`] input | Success output |
//! |-------|----------------------|----------------|
//! | CA pair | `&CaChain` | `&Certificate` (ASK) |
//! | Full chain | `&Chain` | `&Certificate` (VCEK/VLEK) |
//! | Certificate | `(&Certificate, &Certificate)` | `()` |
//! | Report (with VEK) | `(&Certificate, &Report)` | `()` |
//! | Report (with chain) | `(&Chain, &Report)` | `()` |
//! | Low-level report | `(SignatureAlgorithm, body, sig, &Certificate)` | `()` |
//!
//! # Recommended workflow
//!
//! ```ignore
//! use sev::{
//!     attestation::{
//!         attester::snp::Firmware,
//!         evidence::snp::{Report, ReportBody},
//!         endorser::snp::Chain,
//!         verifier::Verifiable,
//!     },
//! };
//!
//! let (raw, Some(certs)) = firmware.get_ext_report(None, None, None)?;
//! let chain = Chain::from_cert_table_der(certs)?;
//! let report = Report::from_bytes(&raw)?;
//!
//! // Verify chain + report signature.
//! (chain, &report).verify()?;
//!
//! // Parse body fields only after verification.
//! let body = ReportBody::try_from((&report, &chain))?;
//! ```
//!
//! [`Report`](crate::attestation::evidence::snp::Report) is a zero-copy view over
//! untrusted bytes. Prefer [`ReportBody::try_from`](crate::attestation::evidence::snp::ReportBody)
//! (with a [`Chain`](crate::attestation::endorser::snp::Chain) or
//! [`Certificate`](crate::attestation::endorser::snp::Certificate)) over parsing
//! [`ReportBody::from_bytes`](crate::attestation::evidence::snp::ReportBody) directly,
//! so signature checks run before typed field access.
//!
//! # Submodules
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`chain`](self::chain) | ARK → ASK → VCEK/VLEK chain verification |
//! | [`cert`](self::cert) / [`cert_nossl`](self::cert_nossl) | X.509 certificate signature checks (backend-specific) |
//! | [`ecdsa`](self::ecdsa) | ECDSA P-384 report signature verification |
//! | [`report`](self::report) | High-level report + chain/VEK verification |
//! | [`signature`](self::signature) | Algorithm-dispatching report signature verification |
//!
//! # Features
//!
//! Requires `verifier`, `snp`, and either `crypto-openssl` or `crypto-rust`.
//! Certificate and signature verification paths are selected at compile time.

mod chain;
mod ecdsa;
mod report;
mod signature;

#[cfg(feature = "crypto-openssl")]
mod cert;

#[cfg(feature = "crypto-rust")]
mod cert_nossl;
