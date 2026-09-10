// SPDX-License-Identifier: Apache-2.0

//! Firmware version triple (major, minor, build).
//!
//! [`FirmwareVersion`] is the canonical semver-style triple used in SEV platform
//! status, SNP attestation report bodies, and as a parsing context for SNP types
//! whose reserved-bit rules changed across firmware releases.
//!
//! Legacy SEV code uses the struct directly ([`FirmwareVersion::new`], ordering,
//! [`std::fmt::Display`]). Wire [`Encoder`](crate::parser::Encoder) /
//! [`Decoder`](crate::parser::Decoder) impls are compiled only with the `snp`
//! feature because SEV never serializes this type through the parser stack.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "snp")]
use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};
#[cfg(feature = "snp")]
use std::io::{Read, Write};

/// Firmware version as major, minor, and build components.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirmwareVersion {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// Build number.
    pub build: u8,
}

impl FirmwareVersion {
    /// Create a firmware version triple.
    pub const fn new(major: u8, minor: u8, build: u8) -> Self {
        Self {
            major,
            minor,
            build,
        }
    }
}

impl std::fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

#[cfg(feature = "snp")]
impl Encoder<()> for FirmwareVersion {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.build, ())?;
        writer.write_bytes(self.minor, ())?;
        writer.write_bytes(self.major, ())?;
        Ok(())
    }
}

#[cfg(feature = "snp")]
impl Decoder<()> for FirmwareVersion {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let build = reader.read_bytes()?;
        let minor = reader.read_bytes()?;
        let major = reader.read_bytes()?;
        Ok(Self {
            major,
            minor,
            build,
        })
    }
}

#[cfg(feature = "snp")]
impl ByteParser<()> for FirmwareVersion {
    type Bytes = [u8; 3];
    const EXPECTED_LEN: Option<usize> = Some(3);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(FirmwareVersion::new(3, 2, 1).to_string(), "3.2.1");
    }

    #[test]
    fn ordering() {
        let v1 = FirmwareVersion::new(1, 0, 0);
        let v2 = FirmwareVersion::new(1, 0, 1);
        let v3 = FirmwareVersion::new(1, 1, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[cfg(feature = "snp")]
    mod wire {
        use super::*;
        use crate::parser::ByteParser;

        #[test]
        fn byte_parser() {
            let bytes = [1, 2, 3];
            let version = FirmwareVersion::from_bytes(&bytes).unwrap();
            assert_eq!(version, FirmwareVersion::new(3, 2, 1));

            let version = FirmwareVersion::new(4, 5, 6);
            let bytes = version.to_bytes().unwrap();
            assert_eq!(bytes, [6, 5, 4]);

            let original = FirmwareVersion::new(7, 8, 9);
            let bytes = original.to_bytes().unwrap();
            let roundtrip = FirmwareVersion::from_bytes(&bytes).unwrap();
            assert_eq!(original, roundtrip);

            assert_eq!(
                <FirmwareVersion as Default>::default(),
                FirmwareVersion::new(0, 0, 0)
            );
        }

        #[test]
        fn edge_cases() {
            let version = FirmwareVersion::new(255, 255, 255);
            assert_eq!(version.to_bytes().unwrap(), [255, 255, 255]);

            let version = FirmwareVersion::new(0, 255, 0);
            assert_eq!(version.to_bytes().unwrap(), [0, 255, 0]);
        }
    }
}
