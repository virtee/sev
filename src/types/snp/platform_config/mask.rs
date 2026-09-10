// SPDX-License-Identifier: Apache-2.0

//! Chip-ID and VCEK masking flags for SNP platform configuration.
//!
//! [`MaskId`] is written through `SNP_SET_CONFIG` to control whether
//! attestation reports zero the chip ID and/or use VLEK instead of VCEK.

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};
use std::io::{Read, Write};

use bitfield::bitfield;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

bitfield! {
    /// Mask ID values that would go into an SNP CONFIG
    ///
    /// | Bit(s) | Name | Description |
    /// |--------|------|-------------|
    /// |0|MASK_CHIP_ID|Indicates that the CHIP_ID field in the attestation report will alwaysbe zero.|
    /// |1|MASK_CHIP_KEY|Indicates that the VCEK is not used in attestation and guest key derivation.|
    #[repr(C)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Default, Copy, Clone, PartialEq, Eq)]
    pub struct MaskId(u32);
    impl Debug;
    /// Indicates that the CHIP_ID field in the attestation report will alwaysbe zero.
    pub mask_chip_id, _: 0;
    /// Indicates that the VCEK is not used in attestation and guest key derivation.
    pub mask_chip_key, _: 1;
}

impl Encoder<()> for MaskId {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

impl Decoder<()> for MaskId {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let mask = reader.read_bytes()?;
        Ok(Self(mask))
    }
}

impl ByteParser<()> for MaskId {
    type Bytes = [u8; 4];
    const EXPECTED_LEN: Option<usize> = Some(4);
}

impl std::fmt::Display for MaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
    MaskID ({}):
    Mask Chip ID: {}
    ABI Chip Key: {}"#,
            self.0,
            self.mask_chip_id(),
            self.mask_chip_key(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ByteParser;

    #[test]
    fn test_mask_id() {
        let mut mask = MaskId(0);
        assert!(!mask.mask_chip_id());

        mask.0 = 0x3;
        assert!(mask.mask_chip_id());
        assert!(mask.mask_chip_key());

        let display_output = format!("{}", mask);
        assert!(display_output.contains("MaskID (3)"));
    }

    #[test]
    fn test_mask_id_operations() {
        let mut mask = MaskId(0);
        assert!(!mask.mask_chip_id());
        assert!(!mask.mask_chip_key());

        mask.0 = 0x3;
        assert!(mask.mask_chip_id());
        assert!(mask.mask_chip_key());

        let display = format!("{}", mask);
        assert!(display.contains("MaskID (3)"));
        assert!(display.contains("Mask Chip ID: true"));
    }

    #[test]
    fn test_mask_id_boundary() {
        let mut mask = MaskId(u32::MAX);
        assert!(mask.mask_chip_id());
        assert!(mask.mask_chip_key());

        mask = MaskId(0);
        assert!(!mask.mask_chip_id());
        assert!(!mask.mask_chip_key());
    }

    #[test]
    fn test_mask_id_deserialization() {
        let test_cases = vec![
            MaskId(0),
            MaskId(0x1),
            MaskId(0x2),
            MaskId(0x3),
            MaskId(u32::MAX),
        ];

        for mask in test_cases {
            let serialized = mask.clone().to_bytes().unwrap();
            let deserialized = MaskId::from_bytes(&serialized).unwrap();
            assert_eq!(mask.0, deserialized.0);
            assert_eq!(mask.mask_chip_id(), deserialized.mask_chip_id());
            assert_eq!(mask.mask_chip_key(), deserialized.mask_chip_key());
        }
    }

    #[test]
    fn test_mask_id_from_bytes() {
        let bytes: [u8; 4] = [0b11, 0b11, 0b11, 0b11];
        let mask_id = MaskId::from_bytes(&bytes).unwrap();
        assert!(mask_id.mask_chip_id());
        assert!(mask_id.mask_chip_key());
    }

    #[test]
    fn test_mask_id_to_bytes() {
        let mask_id = MaskId(0x01020304);
        let bytes = mask_id.to_bytes().unwrap();
        assert_eq!(bytes, [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_mask_id_default() {
        let mask_id: MaskId = Default::default();
        assert_eq!(mask_id.0, 0);
    }
}
