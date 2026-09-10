// SPDX-License-Identifier: Apache-2.0

//! AMD Milan ARK and ASK certificates.
//!
//! Provenance: <https://developer.amd.com/wp-content/resources/ask_ark_milan.cert>

/// The public Milan ARK certificate.
pub const ARK: &[u8] = include_bytes!("ark.cert");

/// The public Milan ASK certificate.
pub const ASK: &[u8] = include_bytes!("ask.cert");
