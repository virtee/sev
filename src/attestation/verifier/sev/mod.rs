// SPDX-License-Identifier: Apache-2.0

//! Legacy SEV attestation verification.

mod cert;
mod report;

// `chain::infer_generation` is crate-internal: `util::cached_chain` needs it to
// build a CA chain for an exported platform chain, but it is not public API.
pub(crate) mod chain;
