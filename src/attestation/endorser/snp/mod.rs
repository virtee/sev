// SPDX-License-Identifier: Apache-2.0

//! SNP endorsement material: AMD certificate chains for report verification.
//!
//! This module implements the RATS **Endorser** role for SEV-SNP. It provides
//! types and parsers for the certificate chain that signs attestation reports:
//! AMD Root Key (ARK) → AMD Signing Key (ASK) → Versioned Chip Endorsement Key
//! (VCEK) or Versioned Loaded Endorsement Key (VLEK).
//!
//! Endorsement material is **trust input** for the verifier — it does not by
//! itself prove a report is authentic until chain and signature checks succeed
//! in [`crate::attestation::verifier::snp`].
//!
//! # Certificate chain
//!
//! ```text
//!  ARK (AMD root)
//!    └── signs ──► ASK (platform signing key)
//!                      └── signs ──► VCEK or VLEK (per-chip endorsement key)
//!                                            └── signs ──► attestation report
//! ```
//!
//! | Type | Role |
//! |------|------|
//! | [`Certificate`] | Single X.509 cert wrapper (OpenSSL or pure-Rust backend) |
//! | [`CaChain`] | ARK + ASK pair ([`ca`](self::ca)) |
//! | [`Chain`] | Full chain: CA + VCEK/VLEK ([`chain`](self::chain)) |
//!
//! # Typical sources
//!
//! | Source | How to build a [`Chain`] |
//! |--------|--------------------------|
//! | Guest extended report | [`Chain::from_cert_table_der`] / [`Chain::from_cert_table_pem`] on entries from [`Firmware::get_ext_report`](crate::attestation::attester::snp::Firmware::get_ext_report) |
//! | Host export / files | [`Chain::from_pem`] or [`Chain::from_der`] |
//! | PEM stack (CA only) | [`CaChain::from_pem_bytes`] (OpenSSL) |
//!
//! # Verification workflow
//!
//! ```ignore
//! use sev::{
//!     attestation::{
//!         attester::snp::Firmware,
//!         evidence::snp::Report,
//!         endorser::snp::Chain,
//!         verifier::Verifiable,
//!     },
//! };
//!
//! let (raw, Some(certs)) = firmware.get_ext_report(None, None, None)?;
//! let chain = Chain::from_cert_table_der(certs)?;
//! let report = Report::from_bytes(&raw)?;
//! chain.verify()?;           // ARK → ASK → VCEK/VLEK
//! (chain, &report).verify()?; // VCEK/VLEK → report signature
//! ```
//!
//! For verified field access, use
//! [`ReportBody::try_from((&report, &chain))`](crate::attestation::evidence::snp::ReportBody).
//!
//! # Features
//!
//! Requires `endorser`, `snp`, and either `crypto-openssl` or `crypto-rust`.
//! The [`Certificate`] backend is selected at compile time; the public type
//! name is the same for both.

/// Certificate Authority (CA) certificates.
pub mod ca;

#[cfg(feature = "crypto-openssl")]
mod cert;
#[cfg(feature = "crypto-rust")]
mod cert_nossl;

mod chain;

#[cfg(feature = "crypto-openssl")]
pub use cert::Certificate;
#[cfg(feature = "crypto-rust")]
pub use cert_nossl::Certificate;

pub use ca::CaChain;
pub use chain::Chain;

use std::io::{Error, ErrorKind, Result};
