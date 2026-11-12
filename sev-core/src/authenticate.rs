// SPDX-License-Identifier: Apache-2.0

//! Signature checks.
//!
//! A type that implements [`Authenticate`] can decide whether a signature
//! belongs to its key. Certificates and other signing keys
//! implement this. The check does not turn the signed artifact into a trusted
//! value. That is [`Verifiable`](crate::Verifiable).

/// A key that can check a signature over a byte string.
///
/// # Examples
///
/// ```
/// use sev_core::Authenticate;
///
/// struct Key(u8);
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
/// Key(7).authenticate(&[7]).unwrap();
/// assert!(Key(7).authenticate(&[9]).is_err());
/// ```
pub trait Authenticate {
    /// Failure reported when the signature does not belong to this key.
    type Error;

    /// Check that `signature` belongs to this key.
    fn authenticate(&self, signature: &[u8]) -> Result<(), Self::Error>;
}
