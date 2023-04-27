// SPDX-License-Identifier: Apache-2.0

//! AMD's Genoa certificates.
//!
//! Certificate provenance: <https://developer.amd.com/wp-content/resources/ask_ark_genoa.cert>
//!
//! For convenience, the certificate chain has been split into individual
//! certificates and are embedded here as byte slices.

/// The public Genoa ARK certificate.
pub const ARK: &[u8] = include_bytes!("ark.cert");

/// The public Genoa ASK certificate.
pub const ASK: &[u8] = include_bytes!("ask.cert");
