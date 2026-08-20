// SPDX-License-Identifier: Apache-2.0

use crate::parser::ByteParser;
use crate::{
    parser::{Decoder, Encoder},
    util::{
        hexline::HexLine,
        parser_helper::{ReadExt, WriteExt},
    },
};

use std::io::{self, Read, Write};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use serde_big_array::BigArray;

#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, PartialOrd, Ord)]
/// ECDSA signature wire layout from an attestation report.
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
    fn decode(reader: &mut impl Read, _: ()) -> io::Result<Self> {
        let r = reader.read_bytes()?;
        let s = reader.read_bytes()?;
        // Firmware signature field is 0x200 bytes; after r and s, the remaining bytes are reserved/padding.
        reader.skip_bytes::<368>()?;
        Ok(Self { r, s })
    }
}

impl Encoder<()> for Signature {
    fn encode(&self, writer: &mut impl Write, _: ()) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ByteParser;

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

    #[test]
    fn test_signature_serialization() {
        let sig: Signature = Default::default();

        let buffer = sig.to_bytes().unwrap();
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
