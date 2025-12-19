// SPDX-License-Identifier: Apache-2.0

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use super::*;

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::{
        hexline::HexLine,
        parser_helper::{ReadExt, WriteExt},
    },
};

use std::io::{Read, Result, Write};

#[cfg(feature = "openssl")]
use crate::certs::snp::{AsLeBytes, FromLe};

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use std::convert::TryFrom;

#[cfg(feature = "openssl")]
use openssl::{bn, ecdsa};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use serde_big_array::BigArray;

#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, PartialOrd, Ord)]
/// ECDSA signature.
pub struct Signature {
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    r: [u8; 72],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    s: [u8; 72],
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            r: [0u8; 72],
            s: [0u8; 72],
        }
    }
}

impl Signature {
    /// Creates a new signature from the values specified
    pub fn new(r: [u8; 72], s: [u8; 72]) -> Self {
        Self { r, s }
    }
    /// Returns the signatures `r` component
    pub fn r(&self) -> &[u8; 72] {
        &self.r
    }

    /// Returns the signatures `s` component
    pub fn s(&self) -> &[u8; 72] {
        &self.s
    }
}

impl Decoder<()> for Signature {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self> {
        let r = reader.read_bytes()?;
        let s = reader.read_bytes()?;
        Ok(Self { r, s })
    }
}

#[cfg(not(feature = "lax-parser"))]
impl Encoder<()> for Signature {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<()> {
        writer.write_bytes(self.r, ())?;
        writer.write_bytes(self.s, ())?;
        // Reserved bytes
        writer.skip_bytes::<368>()?;
        Ok(())
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Signature {{ r:{:?}, s:{:?} }}",
            self.r.iter(),
            self.s.iter()
        )
    }
}

impl ByteParser<()> for Signature {
    type Bytes = [u8; 512];
    const EXPECTED_LEN: Option<usize> = Some(512);
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
            r#"Signature:
  R:{}
  S:{}"#,
            HexLine(&self.r),
            HexLine(&self.s)
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
        let sig: Signature = Default::default();
        assert_eq!(sig.r(), &[0u8; 72]);
        assert_eq!(sig.s(), &[0u8; 72]);
    }

    #[test]
    fn test_signature_getters() {
        let sig: Signature = Signature {
            r: [1u8; 72],
            s: [2u8; 72],
        };
        assert_eq!(sig.r(), &[1u8; 72]);
        assert_eq!(sig.s(), &[2u8; 72]);
    }

    #[test]
    fn test_signature_eq() {
        let sig1: Signature = Default::default();
        let sig2: Signature = Default::default();
        let sig3: Signature = Signature {
            r: [1u8; 72],
            s: [0u8; 72],
        };

        assert_eq!(sig1, sig2);
        assert_ne!(sig1, sig3);
    }

    #[test]
    fn test_signature_ord() {
        let sig1: Signature = Default::default();
        let sig2: Signature = Signature {
            r: [1u8; 72],
            s: [0u8; 72],
        };

        assert!(sig1 < sig2);
    }

    #[test]
    fn test_signature_debug() {
        let sig: Signature = Default::default();
        let debug_str: String = format!("{:?}", sig);
        assert!(debug_str.starts_with("Signature { r:"));
        assert!(debug_str.contains(", s:"));
    }

    #[test]
    fn test_signature_display() {
        let sig: Signature = Default::default();
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
            let sig: Signature = Default::default();
            let ecdsa_sig: ecdsa::EcdsaSig = (&sig).try_into().unwrap();
            assert_eq!(ecdsa_sig.r().to_vec(), vec![]);
            assert_eq!(ecdsa_sig.s().to_vec(), vec![]);
        }

        #[test]
        fn test_try_into_vec() {
            let sig: Signature = Default::default();
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
            let signature: Signature = Default::default();

            let _p384_sig: p384::ecdsa::Signature = (&signature).try_into().unwrap();
        }

        #[test]
        fn test_try_into_p384_signature() {
            // Test with non-zero values
            let sig = Signature {
                r: [1u8; 72],
                s: [2u8; 72],
            };
            let p384_sig: p384::ecdsa::Signature = (&sig).try_into().unwrap();
            assert_eq!(p384_sig.r().to_bytes().as_slice(), &[1u8; 48]);
            assert_eq!(p384_sig.s().to_bytes().as_slice(), &[2u8; 48]);
        }
    }

    #[cfg(not(feature = "lax-parser"))]
    #[test]
    fn test_signature_serialization() {
        let sig: Signature = Default::default();

        let buffer = sig.to_bytes().unwrap();
        // Decode back
        let decoded = Signature::from_bytes(&buffer).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn test_signature_max_values() {
        let sig: Signature = Signature {
            r: [0xFF; 72],
            s: [0xFF; 72],
        };
        assert_eq!(sig.r(), &[0xFF; 72]);
        assert_eq!(sig.s(), &[0xFF; 72]);
    }
}
