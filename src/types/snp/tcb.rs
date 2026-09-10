// SPDX-License-Identifier: Apache-2.0

//! SNP Trusted Computing Base (TCB) version encoding.
//!
//! [`TcbVersion`] serializes to eight bytes whose field order depends on
//! [`Generation`](crate::types::shared::Generation): Milan/Genoa
//! use the legacy layout; Turin/Venice add an FMC SVN byte. Always pass the
//! correct generation to [`ByteParser::from_bytes_with`](crate::parser::ByteParser::from_bytes_with).

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    types::shared::Generation,
    util::parser_helper::{validate_reserved, ReadExt, WriteExt},
};
use std::{
    convert::TryFrom,
    fmt::{self, Display},
    io::{Read, Write},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Internal selector for known serialized TCB version layouts.
///
/// The TCB version is encoded as an 8-byte value, but the meaning of each byte
/// depends on the [`Generation`] of the host CPU.
///
/// - [`TcbVariant::LegacyTcb`] is used for Milan and Genoa.
/// - [`TcbVariant::TurinTcb`] is used for Turin and Venice.
pub(crate) enum TcbVariant {
    /// Legacy TCB version layout.
    ///
    /// - byte 0: bootloader SVN
    /// - byte 1: PSP OS / TEE SVN
    /// - bytes 2..6: reserved
    /// - byte 6: SNP firmware SVN
    /// - byte 7: microcode SVN
    LegacyTcb,

    /// Turin-style TCB version layout.
    ///
    /// - byte 0: FMC firmware SVN
    /// - byte 1: bootloader SVN
    /// - byte 2: PSP OS / TEE SVN
    /// - byte 3: SNP firmware SVN
    /// - bytes 4..7: reserved
    /// - byte 7: microcode SVN
    TurinTcb,
}

/// TcbVersion represents the version of the firmware.
///
/// (Chapter 2.2; Table 3)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct TcbVersion {
    /// Current FMC fw version
    /// SVN of FMC fw
    pub fmc: Option<u8>,
    /// Current bootloader version.
    /// SVN of PSP bootloader.
    pub bootloader: u8,
    /// Current PSP OS version.
    /// SVN of PSP operating system.
    pub tee: u8,
    /// Version of the SNP firmware.
    /// Security Version Number (SVN) of SNP firmware.
    pub snp: u8,
    /// Lowest current patch level of all the cores.
    pub microcode: u8,
}

impl TryFrom<(&[u8], TcbVariant)> for TcbVersion {
    type Error = std::io::Error;

    fn try_from(value: (&[u8], TcbVariant)) -> Result<Self, Self::Error> {
        let (bytes, variant) = value;
        match variant {
            TcbVariant::LegacyTcb => {
                validate_reserved(&bytes[2..6], 2)?;
                Ok(Self {
                    fmc: None,
                    bootloader: bytes[0],
                    tee: bytes[1],
                    snp: bytes[6],
                    microcode: bytes[7],
                })
            }
            TcbVariant::TurinTcb => {
                validate_reserved(&bytes[4..7], 4)?;
                Ok(Self {
                    fmc: Some(bytes[0]),
                    bootloader: bytes[1],
                    tee: bytes[2],
                    snp: bytes[3],
                    microcode: bytes[7],
                })
            }
        }
    }
}

impl Encoder<Generation> for TcbVersion {
    fn encode(
        &self,
        writer: &mut impl Write,
        generation: Generation,
    ) -> Result<(), std::io::Error> {
        let buffer = match generation {
            Generation::Milan | Generation::Genoa => self.to_legacy_bytes(),
            Generation::Turin | Generation::Venice => self.to_turin_bytes(),
            #[cfg(feature = "sev")]
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Unsupported Processor Generation for TCB writing",
                ))
            }
        };
        writer.write_bytes(buffer, ())?;
        Ok(())
    }
}

impl Decoder<Generation> for TcbVersion {
    fn decode(reader: &mut impl Read, generation: Generation) -> Result<Self, std::io::Error> {
        let bytes: [u8; 8] = reader.read_bytes()?;
        match generation {
            Generation::Milan | Generation::Genoa => {
                TcbVersion::try_from((bytes.as_slice(), TcbVariant::LegacyTcb))
            }
            Generation::Turin | Generation::Venice => {
                TcbVersion::try_from((bytes.as_slice(), TcbVariant::TurinTcb))
            }
            #[cfg(feature = "sev")]
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Unsupported Processor Generation for TCB parsing",
            )),
        }
    }
}

impl ByteParser<Generation> for TcbVersion {
    type Bytes = [u8; 8];
    const EXPECTED_LEN: Option<usize> = Some(8);
}

impl TcbVersion {
    pub(crate) fn to_legacy_bytes(self) -> [u8; 8] {
        [
            self.bootloader,
            self.tee,
            0,
            0,
            0,
            0,
            self.snp,
            self.microcode,
        ]
    }

    pub(crate) fn to_turin_bytes(self) -> [u8; 8] {
        [
            self.fmc.unwrap_or(0),
            self.bootloader,
            self.tee,
            self.snp,
            0,
            0,
            0,
            self.microcode,
        ]
    }

    /// Creates a new instance of a TcbVersion
    pub fn new(fmc: Option<u8>, bootloader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        Self {
            fmc,
            bootloader,
            tee,
            snp,
            microcode,
        }
    }
}

impl Display for TcbVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"TCB Version:
  Microcode:   {}
  SNP:         {}
  TEE:         {}
  Boot Loader: {}
  FMC:         {}"#,
            self.microcode,
            self.snp,
            self.tee,
            self.bootloader,
            self.fmc.map_or("None".to_string(), |fmc| fmc.to_string())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcb_version() {
        let tcb = TcbVersion::new(None, 1, 2, 3, 4);
        assert_eq!(tcb.bootloader, 1);
        assert_eq!(tcb.tee, 2);
        assert_eq!(tcb.snp, 3);
        assert_eq!(tcb.microcode, 4);

        let display = format!("{tcb}");
        assert!(display.contains("Microcode:   4"));
        assert!(display.contains("SNP:         3"));
        assert!(display.contains("TEE:         2"));
        assert!(display.contains("Boot Loader: 1"));
    }

    #[test]
    fn test_tcb_version_default() {
        let tcb_version = TcbVersion::default();
        assert_eq!(tcb_version.bootloader, 0);
        assert_eq!(tcb_version.tee, 0);
        assert_eq!(tcb_version.snp, 0);
        assert_eq!(tcb_version.microcode, 0);
    }

    #[test]
    fn test_tcb_version_legacy_deserialization() {
        let tcb = TcbVersion::new(None, 1, 2, 3, 4);

        let serialized = tcb.to_legacy_bytes();
        let deserialized = TcbVersion::from_bytes_with(&serialized, Generation::Milan).unwrap();

        assert_eq!(tcb, deserialized);
    }

    #[test]
    fn test_tcb_version_turin_deserialization() {
        let tcb = TcbVersion::new(Some(1), 2, 3, 4, 5);

        let serialized = tcb.to_turin_bytes();
        let deserialized = TcbVersion::from_bytes_with(&serialized, Generation::Turin).unwrap();

        assert_eq!(tcb, deserialized);
    }

    #[test]
    fn test_version_comparisons() {
        let v1 = TcbVersion::new(None, 1, 2, 3, 4);
        let v2 = TcbVersion::new(None, 1, 2, 3, 5);
        let v3 = TcbVersion::new(None, 1, 2, 3, 4);

        assert!(v1 < v2);
        assert_eq!(v1, v3);
        assert!(v2 > v1);
        assert!(v1.partial_cmp(&v2).unwrap().is_lt());
    }
}
