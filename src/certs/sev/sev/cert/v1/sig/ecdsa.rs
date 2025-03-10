// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use {super::*, openssl::ecdsa};

use crate::util::array::Array;

use serde::{Deserialize, Serialize};

const SIG_PIECE_SIZE: usize = std::mem::size_of::<[u8; 72]>();

/// An ECDSA Signature.
#[repr(C)]
#[derive(Default, Copy, Clone, Deserialize, Serialize)]
pub struct Signature {
    r: Array<u8, 72>,

    s: Array<u8, 72>,

    _reserved: Array<u8, { 512 - (SIG_PIECE_SIZE * 2) }>,
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

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Signature:
  R: {}
  S: {}
            "#,
            self.r, self.s
        )
    }
}

#[cfg(feature = "openssl")]
impl From<ecdsa::EcdsaSig> for Signature {
    #[inline]
    fn from(value: ecdsa::EcdsaSig) -> Self {
        Signature {
            r: Array(value.r().as_le_bytes()),
            s: Array(value.s().as_le_bytes()),
            _reserved: Array([0; 512 - (SIG_PIECE_SIZE * 2)]),
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
        let r = bn::BigNum::from_le(&*value.r)?;
        let s = bn::BigNum::from_le(&*value.s)?;
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
