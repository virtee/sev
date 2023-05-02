// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use {super::*, openssl::ecdsa};

use crate::util::hexdump;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

const SIG_PIECE_SIZE: usize = std::mem::size_of::<[u8; 72]>();

/// An ECDSA Signature.
#[repr(C)]
#[derive(Copy, Clone, Deserialize, Serialize)]
pub struct Signature {
    #[serde(with = "BigArray")]
    r: [u8; 72],
    #[serde(with = "BigArray")]
    s: [u8; 72],
    #[serde(with = "BigArray")]
    _reserved: [u8; 512 - (SIG_PIECE_SIZE * 2)],
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

#[allow(clippy::derivable_impls)]
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

#[cfg(feature = "openssl")]
impl TryFrom<&Signature> for Vec<u8> {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::try_from(value)?.to_der()?)
    }
}
