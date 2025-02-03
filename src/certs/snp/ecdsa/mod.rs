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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_default() {
        let sig: Signature = Signature::default();
        assert_eq!(sig.r(), &[0u8; 72]);
        assert_eq!(sig.s(), &[0u8; 72]);
    }

    #[test]
    fn test_signature_getters() {
        let sig: Signature = Signature {
            r: [1u8; 72],
            s: [2u8; 72],
            _reserved: [0u8; 512 - (SIG_PIECE_SIZE * 2)],
        };
        assert_eq!(sig.r(), &[1u8; 72]);
        assert_eq!(sig.s(), &[2u8; 72]);
    }

    #[test]
    fn test_signature_eq() {
        let sig1: Signature = Signature::default();
        let sig2: Signature = Signature::default();
        let sig3: Signature = Signature {
            r: [1u8; 72],
            s: [0u8; 72],
            _reserved: [0u8; 512 - (SIG_PIECE_SIZE * 2)],
        };

        assert_eq!(sig1, sig2);
        assert_ne!(sig1, sig3);
    }

    #[test]
    fn test_signature_ord() {
        let sig1: Signature = Signature::default();
        let sig2: Signature = Signature {
            r: [1u8; 72],
            s: [0u8; 72],
            _reserved: [0u8; 512 - (SIG_PIECE_SIZE * 2)],
        };

        assert!(sig1 < sig2);
    }

    #[test]
    fn test_signature_debug() {
        let sig: Signature = Signature::default();
        let debug_str: String = format!("{:?}", sig);
        assert!(debug_str.starts_with("Signature { r: "));
        assert!(debug_str.contains(", s: "));
    }

    #[test]
    fn test_signature_display() {
        let sig: Signature = Signature::default();
        let display_str: String = format!("{}", sig);
        assert!(display_str.contains("Signature:"));
        assert!(display_str.contains("R:"));
        assert!(display_str.contains("S:"));
    }

    #[cfg(feature = "openssl")]
    mod openssl_tests {
        use super::*;
        use openssl::bn::BigNum;
        use std::convert::TryInto;

        #[test]
        fn test_from_ecdsa_sig() {
            let r = BigNum::from_dec_str("123").unwrap();
            let s = BigNum::from_dec_str("456").unwrap();
            let ecdsa_sig = ecdsa::EcdsaSig::from_private_components(r, s).unwrap();
            let sig: Signature = ecdsa_sig.into();
            assert_ne!(sig.r(), &[0u8; 72]);
            assert_ne!(sig.s(), &[0u8; 72]);
        }

        #[test]
        fn test_try_from_bytes() {
            let r = BigNum::from_dec_str("123").unwrap();
            let s = BigNum::from_dec_str("456").unwrap();
            let ecdsa_sig = ecdsa::EcdsaSig::from_private_components(r, s).unwrap();
            let der = ecdsa_sig.to_der().unwrap();
            let sig = Signature::try_from(der.as_slice()).unwrap();
            assert_ne!(sig.r(), &[0u8; 72]);
            assert_ne!(sig.s(), &[0u8; 72]);
        }

        #[test]
        fn test_try_into_ecdsa_sig() {
            let sig = Signature::default();
            let ecdsa_sig: ecdsa::EcdsaSig = (&sig).try_into().unwrap();
            assert_eq!(ecdsa_sig.r().to_vec(), vec![]);
            assert_eq!(ecdsa_sig.s().to_vec(), vec![]);
        }

        #[test]
        fn test_try_into_vec() {
            let sig = Signature::default();
            let der: Vec<u8> = (&sig).try_into().unwrap();
            assert!(!der.is_empty());
        }
    }

    #[cfg(feature = "crypto_nossl")]
    mod crypto_nossl_tests {
        use super::*;
        use std::convert::TryInto;

        #[test]
        #[should_panic]
        fn test_try_into_p384_signature_failure() {
            let signature: Signature = Signature::default();

            let _p384_sig: p384::ecdsa::Signature = (&signature).try_into().unwrap();
        }

        #[test]
        fn test_try_into_p384_signature() {
            // Test with non-zero values
            let sig = Signature {
                r: [1u8; 72],
                s: [2u8; 72],
                _reserved: [0u8; 512 - (SIG_PIECE_SIZE * 2)],
            };
            let p384_sig: p384::ecdsa::Signature = (&sig).try_into().unwrap();
            assert_eq!(p384_sig.r().to_bytes().as_slice(), &[1u8; 48]);
            assert_eq!(p384_sig.s().to_bytes().as_slice(), &[2u8; 48]);
        }
    }

    #[test]
    fn test_signature_serde() {
        let sig: Signature = Signature::default();
        let serialized: Vec<u8> = bincode::serialize(&sig).unwrap();
        let deserialized: Signature = bincode::deserialize(&serialized).unwrap();
        assert_eq!(sig, deserialized);
    }

    #[test]
    fn test_signature_max_values() {
        let sig: Signature = Signature {
            r: [0xFF; 72],
            s: [0xFF; 72],
            _reserved: [0u8; 512 - (SIG_PIECE_SIZE * 2)],
        };
        assert_eq!(sig.r(), &[0xFF; 72]);
        assert_eq!(sig.s(), &[0xFF; 72]);
    }
}
