// SPDX-License-Identifier: Apache-2.0

/// ECDSA signatures.
pub mod ecdsa;

#[cfg(feature = "openssl")]
/// Certificate Authority (CA) certificates.
pub mod ca;

#[cfg(feature = "openssl")]
/// Built-in certificates for Milan and Genoa machines.
pub mod builtin;

#[cfg(feature = "openssl")]
mod cert;

#[cfg(feature = "openssl")]
mod chain;

#[cfg(feature = "openssl")]
pub use cert::Certificate;

#[cfg(feature = "openssl")]
pub use chain::Chain;

use std::io::Result;

#[cfg(feature = "openssl")]
use std::io::{Error, ErrorKind};

#[cfg(feature = "openssl")]
use openssl::x509::X509;

#[cfg(feature = "openssl")]
#[allow(dead_code)]
struct Body;

#[cfg(feature = "openssl")]
/// An interface for types that may contain entities such as
/// signatures that must be verified.
pub trait Verifiable {
    /// An output type for successful verification.
    type Output;

    /// Self-verifies signatures.
    fn verify(self) -> Result<Self::Output>;
}

#[cfg(feature = "openssl")]
/// An interface for types that can sign another type (i.e., a certificate).
pub trait Signer<T> {
    /// The now-signed type.
    type Output;

    /// Signs the target.
    fn sign(&self, target: &mut T) -> Result<Self::Output>;
}

pub(crate) trait FromLe: Sized {
    fn from_le(value: &[u8]) -> Result<Self>;
}

pub(crate) trait AsLeBytes<T> {
    fn as_le_bytes(&self) -> T;
}

#[cfg(feature = "openssl")]
impl FromLe for openssl::bn::BigNum {
    #[inline]
    fn from_le(value: &[u8]) -> Result<Self> {
        Ok(Self::from_slice(
            &value.iter().rev().cloned().collect::<Vec<_>>(),
        )?)
    }
}

#[cfg(feature = "openssl")]
impl AsLeBytes<[u8; 72]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 72] {
        let mut buf = [0u8; 72];

        for (i, b) in self.to_vec().into_iter().rev().enumerate() {
            buf[i] = b;
        }

        buf
    }
}

#[cfg(feature = "openssl")]
impl AsLeBytes<[u8; 512]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 512] {
        let mut buf = [0u8; 512];

        for (i, b) in self.to_vec().into_iter().rev().enumerate() {
            buf[i] = b;
        }

        buf
    }
}
