// SPDX-License-Identifier: Apache-2.0

//! Common verification interface for attestation evidence and endorsements.
//!
//! Types that carry signatures, certificate chains, or other evidence implement
//! [`Verifiable`] so verification logic stays uniform across SNP, legacy SEV,
//! and future backends.

use std::io::Result;

/// A type whose authenticity can be checked cryptographically.
///
/// Implementors represent a verification **input** — a certificate pair, an
/// endorsement chain, an attestation report, or a combination thereof. Calling
/// [`.verify()`](Self::verify) runs the appropriate signature and chain checks
/// and returns either a successful [`Output`](Self::Output) or an
/// [`std::io::Error`].
///
/// # Output type
///
/// Most impls return `()` on success. Chain verification impls may return a
/// trusted reference instead — for example, `&Certificate` for a validated
/// VCEK/VLEK after walking an SNP chain.
///
/// # SNP implementors
///
/// See [`crate::attestation::verifier::snp`] for the full set. Common entry
/// points include:
///
/// - `(&Chain, &Report).verify()` — validate chain and report signature
/// - `(&Certificate, &Report).verify()` — verify report with a trusted VEK
/// - `(&Certificate, &Certificate).verify()` — X.509 issuer → subject check
///
/// # Legacy SEV implementors
///
/// See [`crate::attestation::verifier::sev`] when the `sev` feature is enabled.
pub trait Verifiable {
    /// Value returned when verification succeeds.
    type Output;

    /// Run verification and return [`Self::Output`] on success.
    ///
    /// Errors indicate a failed signature, an invalid chain link, or another
    /// cryptographic check failure. They do not distinguish individual failure
    /// modes beyond the error message.
    fn verify(self) -> Result<Self::Output>;
}
