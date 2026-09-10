// SPDX-License-Identifier: Apache-2.0

//! AMD Rome ARK and ASK certificates.
//!
//! Provenance: <https://developer.amd.com/wp-content/resources/ask_ark_rome.cert>

/// The public Rome ARK certificate.
pub const ARK: &[u8] = include_bytes!("ark.cert");

/// The public Rome ASK certificate.
pub const ASK: &[u8] = include_bytes!("ask.cert");
