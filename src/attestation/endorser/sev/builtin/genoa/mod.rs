// SPDX-License-Identifier: Apache-2.0

//! AMD Genoa ARK and ASK certificates.
//!
//! Provenance: <https://developer.amd.com/wp-content/resources/ask_ark_genoa.cert>

/// The public Genoa ARK certificate.
pub const ARK: &[u8] = include_bytes!("ark.cert");

/// The public Genoa ASK certificate.
pub const ASK: &[u8] = include_bytes!("ask.cert");
