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
    /// Version 2 PlatformInfo bitfield
    /// A structure with a bit-field unsigned 64 bit integer:
    /// Bit 0 representing the status of SMT enablement.
    /// Bit 1 representing the status of TSME enablement.
    /// Bit 2 indicates if ECC memory is used.
    /// Bit 3 indicates if RAPL is disabled.
    /// Bit 4 indicates if ciphertext hiding is enabled
    /// Bit 5 indicates that alias detection has completed since the last system reset and there are no aliasing addresses. Resets to 0.
    /// Bit 6 reserved
    /// Bit 7 indicates that SEV-TIO is enabled.
    /// Bits 8-63 are reserved.
    #[repr(C)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PlatformInfo(u64);
    impl Debug;
    /// Returns the bit state of SMT
    pub smt_enabled, _: 0;
    /// Returns the bit state of TSME.
    pub tsme_enabled, _: 1;
    /// Indicates that the platform is currently using ECC memory
    pub ecc_enabled, _: 2;
    /// Indicates that the RAPL feature is disabled
    pub rapl_disabled, _: 3;
    /// Indicates that ciphertext hiding is enabled
    pub ciphertext_hiding_enabled, _: 4;
    /// Indicates that alias detection has completed since the last system reset and there are no aliasing addresses. Resets to 0.
    pub alias_check_complete, _: 5;
    /// Indicates that SEV-TIO is enabled.
    pub tio_enabled, _ : 7

}

impl PlatformInfo {
    // Bit 2: ECC_ENABLED (added in v1.55)
    const ECC_BIT_2: u64 = 1u64 << 2;
    // Bit 3: RAPL_DISABLED (added in v1.55)
    const RAPL_BIT_3: u64 = 1u64 << 3;
    // Bit 4: CIPHERTEXT_HIDING_ENABLED (added in v1.55)
    const CIPHERTEXT_HIDING_BIT_4: u64 = 1u64 << 4;
    // Bit 5: ALIAS_CHECK_COMPLETE (added in v1.57)
    const ALIAS_CHECK_BIT_5: u64 = 1u64 << 5;
    // Bit 6: Reserved (always MBZ)
    const RESERVED_BIT_6: u64 = 1u64 << 6;
    // Bit 7: TIO_ENABLED (added in v1.56)
    const TIO_BIT_7: u64 = 1u64 << 7;
    // Bits 8-63: Reserved (always MBZ)
    const RESERVED_BITS_8_63: u64 = (!0u64) << 8;

    // FirmwareVersion constants
    const VERSION_1_55: FirmwareVersion = FirmwareVersion {
        major: 1,
        minor: 55,
        build: 0,
    };
    const VERSION_1_56: FirmwareVersion = FirmwareVersion {
        major: 1,
        minor: 56,
        build: 0,
    };
    const VERSION_1_57: FirmwareVersion = FirmwareVersion {
        major: 1,
        minor: 57,
        build: 0,
    };

    fn validate_reserved_bits(self, version: FirmwareVersion) -> std::io::Result<()> {
        let raw = self.0;

        // Bit 6 and bits 8-63 are always reserved
        if (raw & Self::RESERVED_BIT_6) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("PlatformInfo bit 6 is reserved and must be zero (raw=0x{raw:016x})"),
            ));
        }

        if (raw & Self::RESERVED_BITS_8_63) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("PlatformInfo bits 8-63 are reserved and must be zero (raw=0x{raw:016x})"),
            ));
        }

        // Bit 2 (ECC_ENABLED) is only defined for firmware v1.55+
        if version < Self::VERSION_1_55 && (raw & Self::ECC_BIT_2) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "PlatformInfo bit 2 (ECC_ENABLED) is only valid for firmware v1.55+ (raw=0x{raw:016x})"
                ),
            ));
        }

        // Bit 3 (RAPL_DISABLED) is only defined for firmware v1.55+
        if version < Self::VERSION_1_55 && (raw & Self::RAPL_BIT_3) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "PlatformInfo bit 3 (RAPL_DISABLED) is only valid for firmware v1.55+ (raw=0x{raw:016x})"
                ),
            ));
        }

        // Bit 4 (CIPHERTEXT_HIDING_ENABLED) is only defined for firmware v1.55+
        if version < Self::VERSION_1_55 && (raw & Self::CIPHERTEXT_HIDING_BIT_4) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "PlatformInfo bit 4 (CIPHERTEXT_HIDING_ENABLED) is only valid for firmware v1.55+ (raw=0x{raw:016x})"
                ),
            ));
        }

        // Bit 5 (ALIAS_CHECK_COMPLETE) is only defined for firmware v1.57+
        if version < Self::VERSION_1_57 && (raw & Self::ALIAS_CHECK_BIT_5) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "PlatformInfo bit 5 (ALIAS_CHECK_COMPLETE) is only valid for firmware v1.57+ (raw=0x{raw:016x})"
                ),
            ));
        }

        // Bit 7 (TIO_ENABLED) is only defined for firmware v1.56+
        if version < Self::VERSION_1_56 && (raw & Self::TIO_BIT_7) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "PlatformInfo bit 7 (TIO_ENABLED) is only valid for firmware v1.56+ (raw=0x{raw:016x})"
                ),
            ));
        }

        Ok(())
    }

    /// Formats the platform info with version-aware display.
    ///
    /// Platform info bits that are not defined for the given firmware version
    /// will be displayed as "None" instead of their actual value.
    ///
    /// # Arguments
    /// * `version` - The firmware version to use for determining which bits are valid
    ///
    /// # Returns
    /// A formatted string representation of the platform info
    pub fn display_for_version(&self, version: FirmwareVersion) -> String {
        let ecc_enabled = if version >= Self::VERSION_1_55 {
            format!("{}", self.ecc_enabled())
        } else {
            "None".to_string()
        };

        let rapl_disabled = if version >= Self::VERSION_1_55 {
            format!("{}", self.rapl_disabled())
        } else {
            "None".to_string()
        };

        let ciphertext_hiding_enabled = if version >= Self::VERSION_1_55 {
            format!("{}", self.ciphertext_hiding_enabled())
        } else {
            "None".to_string()
        };

        let alias_check_complete = if version >= Self::VERSION_1_57 {
            format!("{}", self.alias_check_complete())
        } else {
            "None".to_string()
        };

        let tio_enabled = if version >= Self::VERSION_1_56 {
            format!("{}", self.tio_enabled())
        } else {
            "None".to_string()
        };

        format!(
            r#"Platform Info ({}):
  SMT Enabled:               {}
  TSME Enabled:              {}
  ECC Enabled:               {}
  RAPL Disabled:             {}
  Ciphertext Hiding Enabled: {}
  Alias Check Complete:      {}
  SEV-TIO Enabled:           {}"#,
            self.0,
            self.smt_enabled(),
            self.tsme_enabled(),
            ecc_enabled,
            rapl_disabled,
            ciphertext_hiding_enabled,
            alias_check_complete,
            tio_enabled
        )
    }
}

impl Display for PlatformInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"Platform Info ({}):
  SMT Enabled:               {}
  TSME Enabled:              {}
  ECC Enabled:               {}
  RAPL Disabled:             {}
  Ciphertext Hiding Enabled: {}
  Alias Check Complete:      {}
  SEV-TIO Enabled:           {}"#,
            self.0,
            self.smt_enabled(),
            self.tsme_enabled(),
            self.ecc_enabled(),
            self.rapl_disabled(),
            self.ciphertext_hiding_enabled(),
            self.alias_check_complete(),
            self.tio_enabled()
        )
    }
}

impl From<u64> for PlatformInfo {
    fn from(value: u64) -> Self {
        PlatformInfo(value)
    }
}

impl From<PlatformInfo> for u64 {
    fn from(value: PlatformInfo) -> Self {
        value.0
    }
}

impl Encoder<()> for PlatformInfo {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

// No checking in case platform info is being parsed outside attestation report
impl Decoder<()> for PlatformInfo {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let raw: u64 = reader.read_bytes()?;
        Ok(PlatformInfo(raw))
    }
}

// Checking reserved bytes according to known reserved bytes in attestation report
impl Decoder<FirmwareVersion> for PlatformInfo {
    fn decode(reader: &mut impl Read, version: FirmwareVersion) -> Result<Self, std::io::Error> {
        let raw: u64 = reader.read_bytes()?;
        let info = PlatformInfo(raw);
        info.validate_reserved_bits(version)?;
        Ok(info)
    }
}

impl ByteParser<()> for PlatformInfo {
    type Bytes = [u8; 8];
    const EXPECTED_LEN: Option<usize> = Some(8);
}

impl ByteParser<FirmwareVersion> for PlatformInfo {
    type Bytes = [u8; 8];
    const EXPECTED_LEN: Option<usize> = Some(8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Decoder, Encoder};

    #[test]
    fn test_platform_info_zeroed() {
        let expected: PlatformInfo = PlatformInfo(0);

        assert!(!expected.smt_enabled());
        assert!(!expected.tsme_enabled());
        assert!(!expected.ecc_enabled());
        assert!(!expected.rapl_disabled());
        assert!(!expected.ciphertext_hiding_enabled());
        assert!(!expected.alias_check_complete());
    }

    #[test]
    fn test_platform_info_full() {
        let expected: PlatformInfo = PlatformInfo(0b111111);

        assert!(expected.smt_enabled());
        assert!(expected.tsme_enabled());
        assert!(expected.ecc_enabled());
        assert!(expected.rapl_disabled());
        assert!(expected.ciphertext_hiding_enabled());
        assert!(expected.alias_check_complete());
    }

    #[test]
    fn test_platform_info_fmt() {
        let expected: &str = r#"Platform Info (0):
  SMT Enabled:               false
  TSME Enabled:              false
  ECC Enabled:               false
  RAPL Disabled:             false
  Ciphertext Hiding Enabled: false
  Alias Check Complete:      false
  SEV-TIO Enabled:           false"#;
        let actual: PlatformInfo = PlatformInfo(0);

        assert_eq!(expected, actual.to_string());
    }
    #[test]
    fn test_platform_info_v2_serialization() {
        let original = PlatformInfo(0b11);
        // Test encoding and decoding with basic bits (SMT, TSME) only
        let mut buffer = [0u8; 8];
        original.encode(&mut buffer.as_mut_slice(), ()).unwrap();
        let decoded = PlatformInfo::decode(&mut buffer.as_slice(), ()).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_platform_v2_info_from_u64() {
        let value: u64 = 0xFFFF;
        let platform_info = PlatformInfo::from(value);
        assert_eq!(platform_info.0, value);

        let value: u64 = 0;
        let platform_info = PlatformInfo::from(value);
        assert_eq!(platform_info.0, value);

        let value: u64 = u64::MAX;
        let platform_info = PlatformInfo::from(value);
        assert_eq!(platform_info.0, value);
    }

    #[test]
    fn test_platform_v2_info_into_u64() {
        let platform_info = PlatformInfo(0xFFFF);
        let value: u64 = platform_info.into();
        assert_eq!(value, 0xFFFF);

        let platform_info = PlatformInfo(0);
        let value: u64 = platform_info.into();
        assert_eq!(value, 0);

        let platform_info = PlatformInfo(u64::MAX);
        let value: u64 = platform_info.into();
        assert_eq!(value, u64::MAX);
    }
}
