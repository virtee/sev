// SPDX-License-Identifier: Apache-2.0

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    types::shared::FirmwareVersion,
    util::parser_helper::{ReadExt, WriteExt},
};

use std::{
    fmt::Display,
    io::{Read, Write},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use bitfield::bitfield;
bitfield! {
    /// When an attestation report is requested, the user can request to have the report to not be signed, or sign with different keys. The user may also
    /// pass in the author key when launching the guest. This field provides that information and will be present in the attestation report.
    ///
    /// | Bit(s) | Name              | Description                                                                                                        >
    /// |--------|-------------------|-------------------------------------------------------------------------------------------------------------------->
    /// | 0      | AUTHOR_KEY_EN     | Indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn. >
    /// | 1      | MASK_CHIP_KEY     | The value of MaskChipKey.                                                                                          >
    /// | 4:2    | SIGNING_KEY       | Encodes the key used to sign this report.                                                                          >
    /// | 5:31   | -                 | Reserved. Must be zero.                                                                                            >
    #[repr(C)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
    pub struct KeyInfo(u32);
    impl Debug;
    /// AUTHOR_KEY_EN field: Indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST
    pub author_key_en, _: 0;
    /// MASK_CHIP_KEY field: The value of MaskChipKey
    /// (0) Firmware signs the attestation report with either the VCEK OR VLEK.
    /// (1) The firmware writes 0s into the SIGNATURE field instead of signing the report.
    pub mask_chip_key, _: 1;
    /// SIGNING_KEY field: Encodes the key used to sign this report.
    /// (0) VCEK
    /// (1) VLEK
    /// (2-6) RESERVED
    /// (7) NONE
    pub signing_key, _: 4,2;

}

impl KeyInfo {
    // Bits 0..4 are defined, bits 5..31 must be zero.
    const RESERVED_MASK: u32 = !0x1F; // 0xFFFF_FFE0

    // Bit 1: MASK_CHIP_KEY (added in v1.53)
    const MASK_CHIP_KEY_BIT_1: u32 = 1u32 << 1;

    // SIGNING_KEY field: bits 2-4
    const SIGNING_KEY_MASK: u32 = 0b111 << 2;

    // FirmwareVersion constants
    const VERSION_1_53: FirmwareVersion = FirmwareVersion {
        major: 1,
        minor: 53,
        build: 0,
    };
    const VERSION_1_54: FirmwareVersion = FirmwareVersion {
        major: 1,
        minor: 54,
        build: 0,
    };

    fn validate_reserved_bits(self, version: FirmwareVersion) -> std::io::Result<()> {
        let raw: u32 = self.0;

        // Bits 5-31 must always be zero
        if (raw & Self::RESERVED_MASK) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("KeyInfo reserved bits 5-31 must be zero (raw=0x{raw:08x})"),
            ));
        }

        // Bit 1 (MASK_CHIP_KEY) is only defined for firmware v1.53+
        if version < Self::VERSION_1_53 && (raw & Self::MASK_CHIP_KEY_BIT_1) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "KeyInfo bit 1 (MASK_CHIP_KEY) is only valid for firmware v1.53+ (raw=0x{raw:08x})"
                ),
            ));
        }

        // SIGNING_KEY = VLEK (value 1) is only defined for firmware v1.54+
        let signing_key = (raw & Self::SIGNING_KEY_MASK) >> 2;
        if version < Self::VERSION_1_54 && signing_key == 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "KeyInfo SIGNING_KEY=VLEK (1) is only valid for firmware v1.54+ (raw=0x{raw:08x})"
                ),
            ));
        }

        Ok(())
    }

    /// Formats the key info with version-aware display.
    ///
    /// Key info fields that are not defined for the given firmware version
    /// will be displayed as "None" instead of their actual value.
    ///
    /// # Arguments
    /// * `version` - The firmware version to use for determining which fields are valid
    ///
    /// # Returns
    /// A formatted string representation of the key info
    pub fn display_for_version(&self, version: FirmwareVersion) -> String {
        let mask_chip_key = if version >= Self::VERSION_1_53 {
            format!("{}", self.mask_chip_key())
        } else {
            "None".to_string()
        };

        let signing_key = if version >= Self::VERSION_1_54 {
            match self.signing_key() {
                0 => "vcek".to_string(),
                1 => "vlek".to_string(),
                7 => "none".to_string(),
                v => format!("unknown ({v})"),
            }
        } else {
            // Pre v1.54 only supports VCEK (0) and NONE (7)
            match self.signing_key() {
                0 => "vcek".to_string(),
                7 => "none".to_string(),
                v => format!("unknown ({v})"),
            }
        };

        format!(
            r#"Key Information:
    author key enabled: {}
    mask chip key:      {}
    signing key:        {}"#,
            self.author_key_en(),
            mask_chip_key,
            signing_key
        )
    }
}

impl Encoder<()> for KeyInfo {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0.to_le_bytes(), ())?;
        Ok(())
    }
}

// No checking in case key info is being parsed outside attestation report
impl Decoder<()> for KeyInfo {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let raw: u32 = reader.read_bytes()?;
        Ok(KeyInfo(raw))
    }
}

// Checking reserved bytes according to known reserved bytes in attestation report
impl Decoder<FirmwareVersion> for KeyInfo {
    fn decode(reader: &mut impl Read, version: FirmwareVersion) -> Result<Self, std::io::Error> {
        let raw: u32 = reader.read_bytes()?;
        let info = KeyInfo(raw);
        info.validate_reserved_bits(version)?;
        Ok(info)
    }
}

impl ByteParser<()> for KeyInfo {
    type Bytes = [u8; 4];
    const EXPECTED_LEN: Option<usize> = Some(4);
}

impl ByteParser<FirmwareVersion> for KeyInfo {
    type Bytes = [u8; 4];
    const EXPECTED_LEN: Option<usize> = Some(4);
}

impl From<u32> for KeyInfo {
    fn from(value: u32) -> Self {
        KeyInfo(value)
    }
}

impl From<KeyInfo> for u32 {
    fn from(value: KeyInfo) -> Self {
        value.0
    }
}

impl Display for KeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let signing_key = match self.signing_key() {
            0 => "vcek",
            1 => "vlek",
            7 => "none",
            _ => "unknown",
        };

        write!(
            f,
            r#"Key Information:
    author key enabled: {}
    mask chip key:      {}
    signing key:        {}"#,
            self.author_key_en(),
            self.mask_chip_key(),
            signing_key
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Decoder, Encoder};

    #[test]
    fn test_key_info_zeroed() {
        let expected: KeyInfo = KeyInfo(0);

        assert!(!expected.author_key_en());
        assert!(!expected.mask_chip_key());

        assert_eq!(expected.signing_key(), 0);
    }

    #[test]
    fn test_key_info_max() {
        let expected: KeyInfo = KeyInfo(0b11111);

        assert!(expected.author_key_en());
        assert!(expected.mask_chip_key());
        assert_eq!(expected.signing_key(), 0b111);
    }

    #[test]
    fn test_key_info_fmt_vcek() {
        let expected: &str = r#"Key Information:
    author key enabled: false
    mask chip key:      false
    signing key:        vcek"#;
        let actual: KeyInfo = KeyInfo(0);

        assert_eq!(expected, actual.to_string());
    }

    #[test]
    fn test_key_info_fmt_vlek() {
        let expected: &str = r#"Key Information:
    author key enabled: false
    mask chip key:      false
    signing key:        vlek"#;
        let actual: KeyInfo = KeyInfo(0b100);

        assert_eq!(expected, actual.to_string());
    }

    #[test]
    fn test_key_info_fmt_none() {
        let expected: &str = r#"Key Information:
    author key enabled: false
    mask chip key:      false
    signing key:        none"#;
        let actual: KeyInfo = KeyInfo(0b11100);

        assert_eq!(expected, actual.to_string());
    }

    #[test]
    fn test_key_info_fmt_unknown() {
        let expected: &str = r#"Key Information:
    author key enabled: false
    mask chip key:      false
    signing key:        unknown"#;
        let actual: KeyInfo = KeyInfo(0b11000);

        assert_eq!(expected, actual.to_string());
    }
    #[test]
    fn test_key_info_serialization() {
        let original = KeyInfo(0b11111);

        // Test encoding and decoding
        let mut buffer = [0u8; 4];
        original.encode(&mut buffer.as_mut_slice(), ()).unwrap();
        let decoded = KeyInfo::decode(&mut buffer.as_slice(), ()).unwrap();

        assert_eq!(original, decoded);
        assert!(decoded.author_key_en());
        assert!(decoded.mask_chip_key());
        assert_eq!(decoded.signing_key(), 0b111);
    }
    #[test]
    fn test_key_info_all_combinations() {
        let mut info = KeyInfo(0);

        // Test VCEK
        assert_eq!(info.signing_key(), 0);
        assert!(!info.author_key_en());

        // Test VLEK
        info = KeyInfo(0b100);
        assert_eq!(info.signing_key(), 1);

        // Test None
        info = KeyInfo(0b11100);
        assert_eq!(info.signing_key(), 7);
    }
    #[test]
    fn test_key_info_from_u32() {
        let value: u32 = 0xFFFF;
        let key_info = KeyInfo::from(value);
        assert_eq!(key_info.0, value);

        let value: u32 = 0;
        let key_info = KeyInfo::from(value);
        assert_eq!(key_info.0, value);

        let value: u32 = u32::MAX;
        let key_info = KeyInfo::from(value);
        assert_eq!(key_info.0, value);
    }

    #[test]
    fn test_key_info_into_u32() {
        let key_info = KeyInfo(0xFFFF);
        let value: u32 = key_info.into();
        assert_eq!(value, 0xFFFF);

        let key_info = KeyInfo(0);
        let value: u32 = key_info.into();
        assert_eq!(value, 0);

        let key_info = KeyInfo(u32::MAX);
        let value: u32 = key_info.into();
        assert_eq!(value, u32::MAX);
    }
}
