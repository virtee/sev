// SPDX-License-Identifier: Apache-2.0

//! AMD's TURIN certificates.
//!
//! Certificate provenance: <https://developer.amd.com/wp-content/resources/ask_ark_turin.cert>
//!
//! For convenience, the certificate chain has been split into individual
//! certificates and are embedded here as byte slices.

/// The public Turin ARK certificate.
pub const ARK: &[u8] = include_bytes!("ark.cert");

/// The public Turin ASK certificate.
pub const ASK: &[u8] = include_bytes!("ask.cert");
