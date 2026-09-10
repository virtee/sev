// SPDX-License-Identifier: Apache-2.0

//! Guest owner identifier types for SNP ID blocks.
//!
//! [`FamilyId`] and [`ImageId`] are 128-bit values provided by the guest owner.
//! The firmware stores them in the ID block and may mix them into derived keys
//! when requested via [`GuestFieldSelect`](crate::types::snp::GuestFieldSelect).

use crate::{
    error::IdBlockError,
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};

use std::{
    convert::{TryFrom, TryInto},
    io::{Read, Write},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Family/image identifier size in bits.
pub const ID_BLK_ID_BITS: usize = 128;

/// Family/image identifier size in bytes.
pub const ID_BLK_ID_BYTES: usize = ID_BLK_ID_BITS / 8;

/// Family ID of the guest, provided by the guest owner and uninterpreted by the firmware.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct FamilyId([u8; ID_BLK_ID_BYTES]);

impl FamilyId {
    /// Create a family ID from raw bytes.
    pub fn new(data: [u8; ID_BLK_ID_BYTES]) -> Self {
        Self(data)
    }

    /// Returns the raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8; ID_BLK_ID_BYTES] {
        &self.0
    }
}

impl Encoder<()> for FamilyId {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

impl Decoder<()> for FamilyId {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        Ok(Self(reader.read_bytes()?))
    }
}

impl ByteParser<()> for FamilyId {
    type Bytes = [u8; ID_BLK_ID_BYTES];
    const EXPECTED_LEN: Option<usize> = Some(ID_BLK_ID_BYTES);
}

impl TryFrom<&[u8]> for FamilyId {
    type Error = IdBlockError;

    fn try_from(bytes: &[u8]) -> Result<Self, IdBlockError> {
        Ok(Self(bytes.try_into()?))
    }
}

/// Image ID of the guest, provided by the guest owner and uninterpreted by the firmware.
pub type ImageId = FamilyId;
