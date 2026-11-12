// SPDX-License-Identifier: Apache-2.0

//! Tokens produced from verified artifacts.
//!
//! Implement [`Attestable`] for the artifact your crate owns.
//! [`Verifiable`](crate::Verifiable) chooses what a successful `verify` returns.
//! A certificate can stay a root for a later `verify` and skip this trait.

/// A verified artifact that can produce an attestation token.
///
/// The token type stays in the crate that implements the trait.
///
/// # Examples
///
/// ```
/// use sev_core::{Attestable, Authenticate, Verifiable};
///
/// struct Key(u8);
/// struct Report { measurement: u8, signature: [u8; 1] }
///
/// impl Authenticate for Key {
///     type Error = &'static str;
///
///     fn authenticate(&self, signature: &[u8]) -> Result<(), Self::Error> {
///         if signature == [self.0] {
///             Ok(())
///         } else {
///             Err("bad signature")
///         }
///     }
/// }
///
/// impl Verifiable<Key> for Report {
///     type Output = Self;
///     type Error = &'static str;
///
///     fn verify(self, root: &Key) -> Result<Self::Output, Self::Error> {
///         root.authenticate(&self.signature)?;
///         Ok(self)
///     }
/// }
///
/// impl Attestable for Report {
///     type Token = u8;
///     type Error = &'static str;
///
///     fn to_attestation_result(&self) -> Result<Self::Token, Self::Error> {
///         Ok(self.measurement)
///     }
/// }
///
/// let report = Report { measurement: 7, signature: [7] }
///     .verify(&Key(7))
///     .unwrap();
/// assert_eq!(report.to_attestation_result().unwrap(), 7);
/// ```
pub trait Attestable {
    /// Token produced from this verified artifact.
    type Token;

    /// Failure reported when a token cannot be produced.
    type Error;

    /// Build the attestation token for this verified artifact.
    fn to_attestation_result(&self) -> Result<Self::Token, Self::Error>;
}
