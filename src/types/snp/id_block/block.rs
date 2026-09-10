// SPDX-License-Identifier: Apache-2.0

//! SNP ID block wire layout.
//!
//! Fixed-size block submitted at guest launch. The
//! [`launch_digest`](IdBlock::launch_digest) field is the expected guest
//! measurement (48-byte SHA-384) that must match the attestation report.

use super::{
    ids::{FamilyId, ImageId},
    DEFAULT_ID_POLICY, DEFAULT_ID_VERSION,
};
use crate::{
    error::IdBlockError,
    parser::{ByteParser, Decoder, Encoder},
    types::snp::{GuestPolicy, SnpLaunchDigest},
    util::parser_helper::{ReadExt, WriteExt},
};

use std::io::{Read, Write};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// SNP ID block wire layout.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdBlock {
    /// Expected launch digest of the guest (measurement).
    pub launch_digest: SnpLaunchDigest,
    /// Family ID provided by the guest owner.
    pub family_id: FamilyId,
    /// Image ID provided by the guest owner.
    pub image_id: ImageId,
    /// ID block format version.
    pub version: u32,
    /// Guest SVN.
    pub guest_svn: u32,
    /// Guest policy.
    pub policy: GuestPolicy,
}

impl Default for IdBlock {
    fn default() -> Self {
        Self {
            launch_digest: Default::default(),
            family_id: Default::default(),
            image_id: Default::default(),
            version: DEFAULT_ID_VERSION,
            guest_svn: Default::default(),
            policy: GuestPolicy(DEFAULT_ID_POLICY),
        }
    }
}

impl Encoder<()> for IdBlock {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.launch_digest, ())?;
        writer.write_bytes(self.family_id, ())?;
        writer.write_bytes(self.image_id, ())?;
        writer.write_bytes(self.version, ())?;
        writer.write_bytes(self.guest_svn, ())?;
        writer.write_bytes(self.policy, ())?;
        Ok(())
    }
}

impl Decoder<()> for IdBlock {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        Ok(Self {
            launch_digest: reader.read_bytes()?,
            family_id: reader.read_bytes()?,
            image_id: reader.read_bytes()?,
            version: reader.read_bytes()?,
            guest_svn: reader.read_bytes()?,
            policy: reader.read_bytes()?,
        })
    }
}

impl ByteParser<()> for IdBlock {
    type Bytes = [u8; Self::LEN];
    const EXPECTED_LEN: Option<usize> = Some(Self::LEN);
}

impl IdBlock {
    const LEN: usize = 96;

    /// Create an ID block from optional field overrides.
    pub fn new(
        ld: Option<SnpLaunchDigest>,
        family_id: Option<FamilyId>,
        image_id: Option<ImageId>,
        svn: Option<u32>,
        policy: Option<GuestPolicy>,
    ) -> Result<Self, IdBlockError> {
        let mut id_block = Self::default();

        if let Some(launch_digest) = ld {
            id_block.launch_digest = launch_digest;
        }
        if let Some(fam_id) = family_id {
            id_block.family_id = fam_id;
        }
        if let Some(img_id) = image_id {
            id_block.image_id = img_id;
        }
        if let Some(guest_svn) = svn {
            id_block.guest_svn = guest_svn;
        }
        if let Some(guest_policy) = policy {
            id_block.policy = guest_policy;
        }

        Ok(id_block)
    }
}
