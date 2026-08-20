// SPDX-License-Identifier: Apache-2.0

//! AMD Turin ARK and ASK certificates.
//!
//! Provenance: <https://developer.amd.com/wp-content/resources/ask_ark_turin.cert>

/// The public Turin ARK certificate.
pub const ARK: &[u8] = include_bytes!("ark.cert");

/// The public Turin ASK certificate.
pub const ASK: &[u8] = include_bytes!("ask.cert");
