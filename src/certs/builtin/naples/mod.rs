// SPDX-License-Identifier: Apache-2.0

//! AMD's Naples certificates.
//!
//! Certificate provenance: <https://developer.amd.com/wp-content/resources/ask_ark_naples.cert>
//!
//! For convenience, the certificate chain has been split into individual
//! certificates and are embedded here as byte slices.

/// The public Naples ARK certificate.
pub const ARK: &[u8] = include_bytes!("ark.cert");

/// The public Naples ASK certificate.
pub const ASK: &[u8] = include_bytes!("ask.cert");
