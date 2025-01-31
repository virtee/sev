// SPDX-License-Identifier: Apache-2.0

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use super::*;

use crate::util::hexdump;

#[cfg(feature = "openssl")]
use crate::certs::snp::{AsLeBytes, FromLe};

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[cfg(feature = "openssl")]
use openssl::{bn, ecdsa};

const SIG_PIECE_SIZE: usize = std::mem::size_of::<[u8; 72]>();
const R_S_SIZE: usize = SIG_PIECE_SIZE * 2usize;

#[repr(C)]
#[derive(Copy, Clone, Deserialize, Serialize, PartialOrd, Ord)]
/// ECDSA signature.
pub struct Signature {
    #[serde(with = "BigArray")]
    r: [u8; 72],
    #[serde(with = "BigArray")]
    s: [u8; 72],
    #[serde(with = "BigArray")]
    _reserved: [u8; 512 - R_S_SIZE],
}

impl Signature {
    /// Returns the signatures `r` component
    pub fn r(&self) -> &[u8; 72] {
        &self.r
    }

    /// Returns the signatures `s` component
    pub fn s(&self) -> &[u8; 72] {
        &self.s
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Signature {{ r: {:?}, s: {:?} }}",
            self.r.iter(),
            self.s.iter()
        )
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.r[..] == other.r[..] && self.s[..] == other.s[..]
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            r: [0u8; 72],
            s: [0u8; 72],
            _reserved: [0u8; (512 - (SIG_PIECE_SIZE * 2))],
        }
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Signature:
  R: {}
  S: {}
            "#,
            hexdump(&self.r),
            hexdump(&self.s)
        )
    }
}

#[cfg(feature = "openssl")]
impl From<ecdsa::EcdsaSig> for Signature {
    #[inline]
    fn from(value: ecdsa::EcdsaSig) -> Self {
        Signature {
            r: value.r().as_le_bytes(),
            s: value.s().as_le_bytes(),
            _reserved: [0; 512 - (SIG_PIECE_SIZE * 2)],
        }
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::from_der(value)?.into())
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Signature> for ecdsa::EcdsaSig {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        let r = bn::BigNum::from_le(&value.r)?;
        let s = bn::BigNum::from_le(&value.s)?;
        Ok(ecdsa::EcdsaSig::from_private_components(r, s)?)
    }
}

#[cfg(feature = "crypto_nossl")]
impl TryFrom<&Signature> for p384::ecdsa::Signature {
    type Error = Error;

    #[inline]
    fn try_from(signature: &Signature) -> Result<Self> {
        let r_big_endian: Vec<u8> = signature.r.iter().copied().take(48).rev().collect();
        let s_big_endian: Vec<u8> = signature.s.iter().copied().take(48).rev().collect();

        use p384::elliptic_curve::generic_array::GenericArray;
        p384::ecdsa::Signature::from_scalars(
            GenericArray::clone_from_slice(&r_big_endian),
            GenericArray::clone_from_slice(&s_big_endian),
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to deserialize signature from scalars: {e:?}"),
            )
        })
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Signature> for Vec<u8> {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::try_from(value)?.to_der()?)
    }
}
