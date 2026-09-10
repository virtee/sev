// SPDX-License-Identifier: Apache-2.0

//! ECDSA P-384 wire layouts for SNP ID authentication blocks.
//!
//! Fixed-size coordinate and signature fields used in [`IdAuth`](super::IdAuth).
//! Coordinates are 72-byte little-endian scalars (576 bits).

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};

use std::io::{Read, Write};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use serde_big_array::BigArray;

pub const ECDSA_POINT_SIZE_BITS: usize = 576;
/// ECDSA coordinate size in bytes (P-384).
pub const ECDSA_POINT_SIZE_BYTES: usize = ECDSA_POINT_SIZE_BITS / 8;
pub(crate) const ECDSA_PUBKEY_RESERVED: usize = 0x403 - 0x94 + 1;
pub(crate) const ECDSA_SIG_RESERVED: usize = 0x1ff - 0x90 + 1;

/// ECDSA signature wire layout used in SNP ID authentication blocks.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SevEcdsaSig {
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    r: [u8; ECDSA_POINT_SIZE_BYTES],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    s: [u8; ECDSA_POINT_SIZE_BYTES],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    reserved: [u8; ECDSA_SIG_RESERVED],
}

impl Default for SevEcdsaSig {
    fn default() -> Self {
        Self {
            r: [0u8; ECDSA_POINT_SIZE_BYTES],
            s: [0u8; ECDSA_POINT_SIZE_BYTES],
            reserved: [0u8; ECDSA_SIG_RESERVED],
        }
    }
}

impl SevEcdsaSig {
    const LEN: usize = 2 * ECDSA_POINT_SIZE_BYTES + ECDSA_SIG_RESERVED;

    /// Construct a signature from raw `r` and `s` components.
    pub fn from_raw(r: [u8; ECDSA_POINT_SIZE_BYTES], s: [u8; ECDSA_POINT_SIZE_BYTES]) -> Self {
        Self {
            r,
            s,
            ..Default::default()
        }
    }
}

impl Encoder<()> for SevEcdsaSig {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.r, ())?;
        writer.write_bytes(self.s, ())?;
        writer.write_bytes(self.reserved, ())?;
        Ok(())
    }
}

impl Decoder<()> for SevEcdsaSig {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        Ok(Self {
            r: reader.read_bytes()?,
            s: reader.read_bytes()?,
            reserved: reader.read_bytes()?,
        })
    }
}

impl ByteParser<()> for SevEcdsaSig {
    type Bytes = [u8; Self::LEN];
    const EXPECTED_LEN: Option<usize> = Some(Self::LEN);
}

/// ECDSA public key coordinate wire layout used in SNP ID authentication blocks.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SevEcdsaKeyData {
    /// X coordinate of the public key.
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    pub qx: [u8; ECDSA_POINT_SIZE_BYTES],
    /// Y coordinate of the public key.
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    pub qy: [u8; ECDSA_POINT_SIZE_BYTES],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    reserved: [u8; ECDSA_PUBKEY_RESERVED],
}

impl Default for SevEcdsaKeyData {
    fn default() -> Self {
        Self {
            qx: [0u8; ECDSA_POINT_SIZE_BYTES],
            qy: [0u8; ECDSA_POINT_SIZE_BYTES],
            reserved: [0u8; ECDSA_PUBKEY_RESERVED],
        }
    }
}

impl SevEcdsaKeyData {
    const LEN: usize = 2 * ECDSA_POINT_SIZE_BYTES + ECDSA_PUBKEY_RESERVED;

    /// Construct public key coordinates from raw `qx` and `qy` values.
    pub fn from_raw(qx: [u8; ECDSA_POINT_SIZE_BYTES], qy: [u8; ECDSA_POINT_SIZE_BYTES]) -> Self {
        Self {
            qx,
            qy,
            ..Default::default()
        }
    }
}

impl Encoder<()> for SevEcdsaKeyData {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.qx, ())?;
        writer.write_bytes(self.qy, ())?;
        writer.write_bytes(self.reserved, ())?;
        Ok(())
    }
}

impl Decoder<()> for SevEcdsaKeyData {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        Ok(Self {
            qx: reader.read_bytes()?,
            qy: reader.read_bytes()?,
            reserved: reader.read_bytes()?,
        })
    }
}

impl ByteParser<()> for SevEcdsaKeyData {
    type Bytes = [u8; Self::LEN];
    const EXPECTED_LEN: Option<usize> = Some(Self::LEN);
}

/// ECDSA public key wire layout used in SNP ID authentication blocks.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct SevEcdsaPubKey {
    /// Curve type for the public key.
    pub curve: u32,
    /// Public key coordinate data.
    pub data: SevEcdsaKeyData,
}

impl SevEcdsaPubKey {
    const LEN: usize = 4 + SevEcdsaKeyData::LEN;

    /// Construct a public key from a curve identifier and coordinate data.
    pub fn new(curve: u32, data: SevEcdsaKeyData) -> Self {
        Self { curve, data }
    }
}

impl Encoder<()> for SevEcdsaPubKey {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.curve.to_le_bytes(), ())?;
        writer.write_bytes(self.data.to_bytes()?, ())?;
        Ok(())
    }
}

impl Decoder<()> for SevEcdsaPubKey {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        Ok(Self {
            curve: u32::from_le_bytes(reader.read_bytes()?),
            data: reader.read_bytes()?,
        })
    }
}

impl ByteParser<()> for SevEcdsaPubKey {
    type Bytes = [u8; Self::LEN];
    const EXPECTED_LEN: Option<usize> = Some(Self::LEN);
}
