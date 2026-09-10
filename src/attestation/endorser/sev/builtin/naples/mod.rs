// SPDX-License-Identifier: Apache-2.0

//! AMD Naples ARK and ASK certificates.
//!
//! Provenance: <https://developer.amd.com/wp-content/resources/ask_ark_naples.cert>

/// The public Naples ARK certificate.
pub const ARK: &[u8] = include_bytes!("ark.cert");

/// The public Naples ASK certificate.
pub const ASK: &[u8] = include_bytes!("ask.cert");
