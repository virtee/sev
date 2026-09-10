// SPDX-License-Identifier: Apache-2.0

//! SNP launch digest (48-byte SHA-384 measurement) wire type.
//!
//! The **launch digest** is the guest's expected measurement at launch. It
//! appears in the ID block ([`IdBlock`](crate::types::snp::IdBlock)), the
//! attestation report body, and is the output of reference measurement
//! ([`crate::attestation::reference::snp::measurement`]).
//!
//! Also referred to as the **expected measurement** in attestation APIs.

use crate::{
    error::MeasurementError,
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};

use std::{
    convert::{TryFrom, TryInto},
    fmt,
    io::{Read, Write},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use serde_big_array::BigArray;

/// Launch digest size in bits (SHA-384).
pub const LD_BITS: usize = 384;

/// Launch digest size in bytes.
pub const LD_BYTES: usize = LD_BITS / 8;

/// SNP launch digest wire type (48-byte SHA-384 hash).
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnpLaunchDigest(#[cfg_attr(feature = "serde", serde(with = "BigArray"))] [u8; LD_BYTES]);

impl Default for SnpLaunchDigest {
    fn default() -> Self {
        Self([0u8; LD_BYTES])
    }
}

impl TryFrom<&[u8]> for SnpLaunchDigest {
    type Error = MeasurementError;

    fn try_from(bytes: &[u8]) -> Result<Self, MeasurementError> {
        Ok(Self(bytes.try_into()?))
    }
}

impl TryInto<Vec<u8>> for SnpLaunchDigest {
    type Error = MeasurementError;

    fn try_into(self) -> Result<Vec<u8>, MeasurementError> {
        Ok(self.0.to_vec())
    }
}

impl Encoder<()> for SnpLaunchDigest {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

impl Decoder<()> for SnpLaunchDigest {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        Ok(Self(reader.read_bytes()?))
    }
}

impl ByteParser<()> for SnpLaunchDigest {
    type Bytes = [u8; LD_BYTES];
    const EXPECTED_LEN: Option<usize> = Some(LD_BYTES);
}

impl fmt::LowerHex for SnpLaunchDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl SnpLaunchDigest {
    /// Create a launch digest from raw bytes.
    pub fn new(data: [u8; LD_BYTES]) -> Self {
        Self(data)
    }

    /// Return the digest as a lowercase hex string.
    pub fn get_hex_ld(self) -> String {
        format!("{:x}", self)
    }

    /// Return the raw 48-byte digest.
    pub fn as_bytes(&self) -> &[u8; LD_BYTES] {
        &self.0
    }
}
