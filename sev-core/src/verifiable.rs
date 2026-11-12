// SPDX-License-Identifier: Apache-2.0

//! Checking an artifact against a root.
//!
//! The artifact implements [`Verifiable`]. [`Verifiable::verify`] calls the
//! root's [`Authenticate::authenticate`](crate::Authenticate::authenticate)
//! and returns the [`Output`](Verifiable::Output) chosen by that implementation.
//!
//! The crate that owns the artifact implements this trait. Artifacts that
//! implement [`Verifiable`] stay out of `sev-types`, because another crate
//! cannot implement a `sev-core` trait for a `sev-types` struct.
//!
//! Implement [`Verifiable`] once, generically over the root, rather than once
//! per root:
//!
//! ```text
//! impl<R: Authenticate> Verifiable<R> for Report { ... }
//! ```
//!
//! That single impl covers every root, including a VEK. A second impl for a
//! specific root in another crate is rejected by the orphan rule, and one in
//! the same crate conflicts with the blanket. Callers pick the root when they
//! call `verify`.

use crate::Authenticate;

/// An artifact whose signature a root can authenticate.
///
/// `Root` implements [`Authenticate`](crate::Authenticate). The implementation
/// calls `root.authenticate` and chooses [`Output`](Verifiable::Output).
///
/// # Examples
///
/// ```
/// use sev_core::{Authenticate, Verifiable};
///
/// struct Key(u8);
/// struct Ask {
///     signature: [u8; 1],
/// }
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
/// impl Verifiable<Key> for Ask {
///     type Output = Self;
///     type Error = &'static str;
///
///     fn verify(self, root: &Key) -> Result<Self::Output, Self::Error> {
///         root.authenticate(&self.signature)?;
///         Ok(self)
///     }
/// }
///
/// let ask = Ask { signature: [7] }.verify(&Key(7)).unwrap();
/// assert_eq!(ask.signature, [7]);
/// assert!(Ask { signature: [1] }.verify(&Key(7)).is_err());
/// ```
pub trait Verifiable<Root: Authenticate>: Sized {
    /// Value produced when the root accepts this artifact.
    type Output;

    /// Failure reported when the root rejects this artifact.
    type Error;

    /// Authenticate `self` with `root` and return [`Output`](Verifiable::Output).
    fn verify(self, root: &Root) -> Result<Self::Output, Self::Error>;
}
