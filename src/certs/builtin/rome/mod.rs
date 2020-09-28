// SPDX-License-Identifier: Apache-2.0

//! AMD's Rome certificates.
//!
//! Certificate provenance: https://developer.amd.com/wp-content/resources/ask_ark_rome.cert
//!
//! For convenience, the certificate chain has been split into individual
//! certificates and are embedded here as byte slices.

/// The public Rome ARK certificate.
pub const ARK: &[u8] = include_bytes!("ark.cert");

/// The public Rome ASK certificate.
pub const ASK: &[u8] = include_bytes!("ask.cert");
