// SPDX-License-Identifier: Apache-2.0

//! Different structures needed to calculate the different pieces needed for ID calculation for pre-attestation

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    md::Md,
    md_ctx::MdCtx,
    nid::Nid,
    pkey::{PKey, Private},
};
use std::{
    convert::{TryFrom, TryInto},
    io::{Read, Write},
};

use crate::{
    error::IdBlockError,
    firmware::guest::GuestPolicy,
    measurement::snp::SnpLaunchDigest,
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use serde_big_array::BigArray;

pub(crate) const DEFAULT_ID_VERSION: u32 = 1;
pub(crate) const DEFAULT_ID_POLICY: u64 = 0x30000;

pub(crate) const CURVE_P384_NID: Nid = openssl::nid::Nid::SECP384R1;
pub(crate) const DEFAULT_KEY_ALGO: u32 = 1;
pub(crate) const CURVE_P384: u32 = 2;

pub(crate) const ID_BLK_ID_BITS: usize = 128;
pub(crate) const ID_BLK_ID_BYTES: usize = ID_BLK_ID_BITS / 8;

pub(crate) const ECDSA_POINT_SIZE_BITS: usize = 576;
pub(crate) const ECDSA_POINT_SIZE_BYTES: usize = ECDSA_POINT_SIZE_BITS / 8;

pub(crate) const ECDSA_PUBKEY_RESERVED: usize = 0x403 - 0x94 + 1;
pub(crate) const ECDSA_SIG_RESERVED: usize = 0x1ff - 0x90 + 1;

/// Family-Id of the guest, provided by the guest owner and uninterpreted by the firmware.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Clone, Copy, Debug)]
pub struct FamilyId([u8; ID_BLK_ID_BYTES]);

impl FamilyId {
    /// Create a new Family Id with the provided data
    pub fn new(data: [u8; ID_BLK_ID_BYTES]) -> Self {
        Self(data)
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
        let id = reader.read_bytes()?;
        Ok(Self(id))
    }
}
impl ByteParser<()> for FamilyId {
    type Bytes = [u8; ID_BLK_ID_BYTES];
    const EXPECTED_LEN: Option<usize> = Some(ID_BLK_ID_BYTES);
}

// Try from slice for Family Id
impl TryFrom<&[u8]> for FamilyId {
    type Error = IdBlockError;

    fn try_from(bytes: &[u8]) -> Result<Self, IdBlockError> {
        Ok(FamilyId(bytes.try_into()?))
    }
}

/// Family-Id of the guest, provided by the guest owner and uninterpreted by the firmware.
/// Esentially the same structure as Family Id.
pub type ImageId = FamilyId;

/// The way the ECDSA SEV signature is strucutred. Need it in this format to calculate the AUTH-ID.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy)]
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
        let r = reader.read_bytes()?;
        let s = reader.read_bytes()?;
        let reserved = reader.read_bytes()?;
        Ok(Self { r, s, reserved })
    }
}

impl SevEcdsaSig {
    const LEN: usize = 2 * ECDSA_POINT_SIZE_BYTES + ECDSA_SIG_RESERVED;
}

impl ByteParser<()> for SevEcdsaSig {
    type Bytes = [u8; Self::LEN];
    const EXPECTED_LEN: Option<usize> = Some(Self::LEN);
}

// Derive SEV ECDSA signature from a private EC KEY
impl TryFrom<(EcKey<Private>, &[u8])> for SevEcdsaSig {
    type Error = IdBlockError;

    fn try_from((priv_key, data): (EcKey<Private>, &[u8])) -> Result<Self, Self::Error> {
        // Mirror what sev-guest (firmware) is doing
        let mut ctx = MdCtx::new().map_err(IdBlockError::CryptoErrorStack)?;

        let pkey = PKey::try_from(priv_key).map_err(IdBlockError::CryptoErrorStack)?;

        ctx.digest_sign_init::<Private>(Some(Md::sha384()), pkey.as_ref())
            .map_err(IdBlockError::CryptoErrorStack)?;

        let sig_size = ctx
            .digest_sign(data, None)
            .map_err(IdBlockError::CryptoErrorStack)?;

        let mut signature = vec![0_u8; sig_size];

        ctx.digest_sign(data, Some(&mut signature))
            .map_err(IdBlockError::CryptoErrorStack)?;

        if signature.len() != sig_size {
            return Err(IdBlockError::SevEcsdsaSigError(
                "Signature is not of the expected length!".to_string(),
            ));
        };

        // Create ECDSA sig from der sig
        let ecdsa_sig =
            EcdsaSig::from_der(signature.as_slice()).map_err(IdBlockError::CryptoErrorStack)?;

        // Extract r and s
        let mut pad_r = ecdsa_sig
            .r()
            .to_vec_padded(ECDSA_POINT_SIZE_BYTES as i32)
            .map_err(IdBlockError::CryptoErrorStack)?;
        pad_r.reverse();

        let mut pad_s = ecdsa_sig
            .s()
            .to_vec_padded(ECDSA_POINT_SIZE_BYTES as i32)
            .map_err(IdBlockError::CryptoErrorStack)?;
        pad_s.reverse();

        let r: [u8; ECDSA_POINT_SIZE_BYTES] = pad_r
            .try_into()
            .map_err(|v: Vec<u8>| IdBlockError::BadVectorError(v.len(), ECDSA_POINT_SIZE_BYTES))?;

        let s: [u8; ECDSA_POINT_SIZE_BYTES] = pad_s
            .try_into()
            .map_err(|v: Vec<u8>| IdBlockError::BadVectorError(v.len(), ECDSA_POINT_SIZE_BYTES))?;

        Ok(SevEcdsaSig {
            r,
            s,
            ..Default::default()
        })
    }
}

/// Data inside the SEV ECDSA key
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy)]
pub struct SevEcdsaKeyData {
    /// QX component of the ECDSA public key
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    pub qx: [u8; ECDSA_POINT_SIZE_BYTES],
    /// QY component of the ECDSA public key
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    pub qy: [u8; ECDSA_POINT_SIZE_BYTES],
    /// Reserved
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
        let qx = reader.read_bytes()?;
        let qy = reader.read_bytes()?;
        let reserved = reader.read_bytes()?;
        Ok(Self { qx, qy, reserved })
    }
}

impl ByteParser<()> for SevEcdsaKeyData {
    type Bytes = [u8; Self::LEN];
    const EXPECTED_LEN: Option<usize> = Some(Self::LEN);
}

/// SEV ECDSA public key. Need it in this format to calculate the AUTH-ID.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Clone, Copy)]
pub struct SevEcdsaPubKey {
    /// curve type for the public key (defaults to P384)
    pub curve: u32,
    /// public key data
    pub data: SevEcdsaKeyData,
}

impl SevEcdsaPubKey {
    const LEN: usize = 4 + SevEcdsaKeyData::LEN; // 4 bytes for curve + data
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
        let curve = u32::from_le_bytes(reader.read_bytes()?);
        let data = reader.read_bytes()?;
        Ok(Self { curve, data })
    }
}

impl ByteParser<()> for SevEcdsaPubKey {
    type Bytes = [u8; Self::LEN]; // 4 bytes for curve + data
    const EXPECTED_LEN: Option<usize> = Some(Self::LEN);
}

// Create SEV ECDSA public key from EC private key
impl TryFrom<&EcKey<Private>> for SevEcdsaPubKey {
    type Error = IdBlockError;

    fn try_from(priv_key: &EcKey<Private>) -> Result<Self, Self::Error> {
        let pub_key = priv_key.public_key();

        let mut sev_key = SevEcdsaPubKey {
            curve: CURVE_P384,
            ..Default::default()
        };

        let mut big_num_ctx = BigNumContext::new().map_err(IdBlockError::CryptoErrorStack)?;

        let curve_group =
            EcGroup::from_curve_name(CURVE_P384_NID).map_err(IdBlockError::CryptoErrorStack)?;

        let mut x = BigNum::new().map_err(IdBlockError::CryptoErrorStack)?;
        let mut y = BigNum::new().map_err(IdBlockError::CryptoErrorStack)?;

        pub_key
            .affine_coordinates(&curve_group, &mut x, &mut y, &mut big_num_ctx)
            .map_err(IdBlockError::CryptoErrorStack)?;

        let mut pad_x = x
            .to_vec_padded(ECDSA_POINT_SIZE_BYTES as i32)
            .map_err(IdBlockError::CryptoErrorStack)?;
        pad_x.reverse();

        let mut pad_y = y
            .to_vec_padded(ECDSA_POINT_SIZE_BYTES as i32)
            .map_err(IdBlockError::CryptoErrorStack)?;
        pad_y.reverse();

        let qx: [u8; ECDSA_POINT_SIZE_BYTES] = pad_x
            .try_into()
            .map_err(|v: Vec<u8>| IdBlockError::BadVectorError(v.len(), ECDSA_POINT_SIZE_BYTES))?;

        let qy: [u8; ECDSA_POINT_SIZE_BYTES] = pad_y
            .try_into()
            .map_err(|v: Vec<u8>| IdBlockError::BadVectorError(v.len(), ECDSA_POINT_SIZE_BYTES))?;

        let key_data = SevEcdsaKeyData {
            qx,
            qy,
            ..Default::default()
        };

        sev_key.data = key_data;

        Ok(sev_key)
    }
}

/// SEV-SNP ID-BLOCK
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug)]
pub struct IdBlock {
    /// The expected launch digest of the guest (aka measurement)
    pub launch_digest: SnpLaunchDigest,
    /// Family ID of the guest, provided by the guest owner and uninterpreted by the firmware.
    pub family_id: FamilyId,
    /// Image ID of the guest, provided by the guest owner and uninterpreted by the firmware.
    pub image_id: ImageId,
    /// Version of the ID block format
    pub version: u32,
    /// SVN of the guest.
    pub guest_svn: u32,
    ///The policy of the guest.
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
        let launch_digest = reader.read_bytes()?;
        let family_id = reader.read_bytes()?;
        let image_id = reader.read_bytes()?;
        let version = reader.read_bytes()?;
        let guest_svn = reader.read_bytes()?;
        let policy = reader.read_bytes()?;
        Ok(Self {
            launch_digest,
            family_id,
            image_id,
            version,
            guest_svn,
            policy,
        })
    }
}

impl ByteParser<()> for IdBlock {
    type Bytes = [u8; Self::LEN];
    const EXPECTED_LEN: Option<usize> = Some(Self::LEN);
}

impl IdBlock {
    const LEN: usize = 96;
    /// Create a new ID-BLOCK with provided parameters.
    pub fn new(
        ld: Option<SnpLaunchDigest>,
        family_id: Option<FamilyId>,
        image_id: Option<ImageId>,
        svn: Option<u32>,
        policy: Option<GuestPolicy>,
    ) -> Result<Self, IdBlockError> {
        let mut id_block = IdBlock::default();

        if let Some(launch_digest) = ld {
            id_block.launch_digest = launch_digest
        };

        if let Some(fam_id) = family_id {
            id_block.family_id = fam_id
        };

        if let Some(img_id) = image_id {
            id_block.image_id = img_id
        };

        if let Some(guest_svn) = svn {
            id_block.guest_svn = guest_svn
        };
        if let Some(guest_policy) = policy {
            id_block.policy = guest_policy
        };

        Ok(id_block)
    }
}

#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy)]
///ID Authentication Information Structure
pub struct IdAuth {
    /// The algorithm of the ID Key. Defaults to P-384
    pub id_key_algo: u32,
    /// The algorithm of the Author Key. Defaults to P-384
    pub author_key_algo: u32,

    #[cfg(feature = "unsafe_parser")]
    /// Reserved 1
    pub reserved1: [u8; Self::ID_AUTH_RESERVED1_BYTES],

    /// The signature of all bytes of the ID block
    pub id_block_sig: SevEcdsaSig,
    /// The public component of the ID key
    pub id_pubkey: SevEcdsaPubKey,

    #[cfg(feature = "unsafe_parser")]
    /// Reserved 2
    pub reserved2: [u8; Self::ID_AUTH_RESERVED2_BYTES],

    /// The signature of the ID_KEY
    pub id_key_sig: SevEcdsaSig,
    /// The public component of the Author key
    pub author_pub_key: SevEcdsaPubKey,

    #[cfg(feature = "unsafe_parser")]
    /// Reserved 3
    pub reserved3: [u8; Self::ID_AUTH_RESERVED3_BYTES],
}

impl Encoder<()> for IdAuth {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.id_key_algo, ())?;
        writer.write_bytes(self.author_key_algo, ())?;

        // Reserved 1
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<{ Self::ID_AUTH_RESERVED1_BYTES }>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved1, ())?;

        writer.write_bytes(self.id_block_sig, ())?;
        writer.write_bytes(self.id_pubkey, ())?;

        // Reserved 2
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<{ Self::ID_AUTH_RESERVED2_BYTES }>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved2, ())?;

        writer.write_bytes(self.id_key_sig, ())?;
        writer.write_bytes(self.author_pub_key, ())?;

        // Reserved 3
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<{ Self::ID_AUTH_RESERVED3_BYTES }>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved3, ())?;

        Ok(())
    }
}

impl Decoder<()> for IdAuth {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let id_key_algo = reader.read_bytes()?;
        let author_key_algo = reader.read_bytes()?;

        // Reserved 1
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<{ Self::ID_AUTH_RESERVED1_BYTES }>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved1 = reader.read_bytes()?;

        let id_block_sig = reader.read_bytes()?;
        let id_pubkey = reader.read_bytes()?;

        // Reserved 2
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<{ Self::ID_AUTH_RESERVED2_BYTES }>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved2 = reader.read_bytes()?;

        let id_key_sig = reader.read_bytes()?;
        let author_pub_key = reader.read_bytes()?;

        // Reserved 3
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<{ Self::ID_AUTH_RESERVED3_BYTES }>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved3 = reader.read_bytes()?;

        #[cfg(not(feature = "unsafe_parser"))]
        {
            Ok(Self {
                id_key_algo,
                author_key_algo,
                id_block_sig,
                id_pubkey,
                id_key_sig,
                author_pub_key,
            })
        }

        #[cfg(feature = "unsafe_parser")]
        {
            Ok(Self {
                id_key_algo,
                author_key_algo,
                reserved1,
                id_block_sig,
                id_pubkey,
                reserved2,
                id_key_sig,
                author_pub_key,
                reserved3,
            })
        }
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

    /// Create a new IdAuth with the provided parameters
    pub fn new(
        id_key_algo: Option<u32>,
        author_key_algo: Option<u32>,
        id_block_sig: SevEcdsaSig,
        id_pubkey: SevEcdsaPubKey,
        id_key_sig: SevEcdsaSig,
        author_pub_key: SevEcdsaPubKey,
    ) -> Self {
        let id_algo = match id_key_algo {
            Some(algo) => algo,
            _ => DEFAULT_KEY_ALGO,
        };

        let key_algo = match author_key_algo {
            Some(algo) => algo,
            _ => DEFAULT_KEY_ALGO,
        };

        #[cfg(not(feature = "unsafe_parser"))]
        {
            Self {
                id_key_algo: id_algo,
                author_key_algo: key_algo,
                id_block_sig,
                id_pubkey,
                id_key_sig,
                author_pub_key,
            }
        }

        #[cfg(feature = "unsafe_parser")]
        {
            Self {
                id_key_algo: id_algo,
                author_key_algo: key_algo,
                reserved1: [0u8; Self::ID_AUTH_RESERVED1_BYTES],
                id_block_sig,
                id_pubkey,
                reserved2: [0u8; Self::ID_AUTH_RESERVED2_BYTES],
                id_key_sig,
                author_pub_key,
                reserved3: [0u8; Self::ID_AUTH_RESERVED3_BYTES],
            }
        }
    }
}

impl Default for IdAuth {
    fn default() -> Self {
        #[cfg(not(feature = "unsafe_parser"))]
        {
            Self {
                id_key_algo: DEFAULT_KEY_ALGO,
                author_key_algo: DEFAULT_KEY_ALGO,
                id_block_sig: Default::default(),
                id_pubkey: Default::default(),
                id_key_sig: Default::default(),
                author_pub_key: Default::default(),
            }
        }

        #[cfg(feature = "unsafe_parser")]
        {
            Self {
                id_key_algo: DEFAULT_KEY_ALGO,
                author_key_algo: DEFAULT_KEY_ALGO,
                reserved1: [0u8; Self::ID_AUTH_RESERVED1_BYTES],
                id_block_sig: Default::default(),
                id_pubkey: Default::default(),
                reserved2: [0u8; Self::ID_AUTH_RESERVED2_BYTES],
                id_key_sig: Default::default(),
                author_pub_key: Default::default(),
                reserved3: [0u8; Self::ID_AUTH_RESERVED3_BYTES],
            }
        }
    }
}

#[derive(Default)]
/// All the calculated pieces needed for ID verfication
pub struct IdMeasurements {
    /// ID-BLOCK
    pub id_block: IdBlock,
    /// ID-AUTH-BLOCK
    pub id_auth: IdAuth,
    /// ID-KEY DIGEST
    pub id_key_digest: SnpLaunchDigest,
    /// AUTH-KEY DIGEST
    pub auth_key_digest: SnpLaunchDigest,
}
