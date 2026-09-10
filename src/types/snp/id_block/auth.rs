// SPDX-License-Identifier: Apache-2.0

//! SNP ID authentication block wire layout.
//!
//! Carries ECDSA P-384 signatures and public keys that authorize an
//! [`IdBlock`](super::IdBlock). Submitted alongside the ID block at launch.

use super::{
    ecdsa::{SevEcdsaPubKey, SevEcdsaSig},
    DEFAULT_KEY_ALGO,
};
use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};

use std::io::{Read, Write};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// SNP ID authentication information block wire layout.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdAuth {
    /// Algorithm of the ID key.
    pub id_key_algo: u32,
    /// Algorithm of the author key.
    pub author_key_algo: u32,
    /// Signature over the ID block bytes.
    pub id_block_sig: SevEcdsaSig,
    /// Public component of the ID key.
    pub id_pubkey: SevEcdsaPubKey,
    /// Signature over the ID key.
    pub id_key_sig: SevEcdsaSig,
    /// Public component of the author key.
    pub author_pub_key: SevEcdsaPubKey,
}

impl Default for IdAuth {
    fn default() -> Self {
        Self {
            id_key_algo: DEFAULT_KEY_ALGO,
            author_key_algo: DEFAULT_KEY_ALGO,
            id_block_sig: Default::default(),
            id_pubkey: Default::default(),
            id_key_sig: Default::default(),
            author_pub_key: Default::default(),
        }
    }
}

impl Encoder<()> for IdAuth {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.id_key_algo, ())?;
        writer.write_bytes(self.author_key_algo, ())?;
        writer
            .skip_bytes::<{ Self::ID_AUTH_RESERVED1_BYTES }>()?
            .write_bytes(self.id_block_sig, ())?;
        writer.write_bytes(self.id_pubkey, ())?;
        writer
            .skip_bytes::<{ Self::ID_AUTH_RESERVED2_BYTES }>()?
            .write_bytes(self.id_key_sig, ())?;
        writer.write_bytes(self.author_pub_key, ())?;
        writer.skip_bytes::<{ Self::ID_AUTH_RESERVED3_BYTES }>()?;
        Ok(())
    }
}

impl Decoder<()> for IdAuth {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let id_key_algo = reader.read_bytes()?;
        let author_key_algo = reader.read_bytes()?;
        reader.skip_bytes::<{ Self::ID_AUTH_RESERVED1_BYTES }>()?;
        let id_block_sig = reader.read_bytes()?;
        let id_pubkey = reader.read_bytes()?;
        reader.skip_bytes::<{ Self::ID_AUTH_RESERVED2_BYTES }>()?;
        let id_key_sig = reader.read_bytes()?;
        let author_pub_key = reader.read_bytes()?;
        reader.skip_bytes::<{ Self::ID_AUTH_RESERVED3_BYTES }>()?;

        Ok(Self {
            id_key_algo,
            author_key_algo,
            id_block_sig,
            id_pubkey,
            id_key_sig,
            author_pub_key,
        })
    }
}

impl ByteParser<()> for IdAuth {
    type Bytes = [u8; Self::LEN];
    const EXPECTED_LEN: Option<usize> = Some(Self::LEN);
}

impl IdAuth {
    const LEN: usize = 0x1000;
    const ID_AUTH_RESERVED1_BYTES: usize = 0x03F - 0x008 + 1;
    const ID_AUTH_RESERVED2_BYTES: usize = 0x67F - 0x644 + 1;
    const ID_AUTH_RESERVED3_BYTES: usize = 0xFFF - 0xC84 + 1;

    /// Create an ID authentication block from the provided components.
    pub fn new(
        id_key_algo: Option<u32>,
        author_key_algo: Option<u32>,
        id_block_sig: SevEcdsaSig,
        id_pubkey: SevEcdsaPubKey,
        id_key_sig: SevEcdsaSig,
        author_pub_key: SevEcdsaPubKey,
    ) -> Self {
        Self {
            id_key_algo: id_key_algo.unwrap_or(DEFAULT_KEY_ALGO),
            author_key_algo: author_key_algo.unwrap_or(DEFAULT_KEY_ALGO),
            id_block_sig,
            id_pubkey,
            id_key_sig,
            author_pub_key,
        }
    }
}
