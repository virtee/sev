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
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};

use crate::{
    error::IdBlockError, firmware::guest::GuestPolicy, measurement::snp::SnpLaunchDigest,
    util::array::Array,
};
use bincode::{Decode, Encode};

pub(crate) const DEFAULT_ID_VERSION: u32 = 1;
pub(crate) const DEFAULT_ID_POLICY: u64 = 0x30000;

pub(crate) const CURVE_P384_NID: Nid = openssl::nid::Nid::SECP384R1;
pub(crate) const DEFAULT_KEY_ALGO: u32 = 1;
pub(crate) const CURVE_P384: u32 = 2;

pub(crate) const ID_BLK_ID_BITS: usize = 128;
pub(crate) const ID_BLK_ID_BYTES: usize = ID_BLK_ID_BITS / 8;

pub(crate) const ID_AUTH_RESERVED1_BYTES: usize = 0x03F - 0x008 + 1;
pub(crate) const ID_AUTH_RESERVED2_BYTES: usize = 0x67F - 0x644 + 1;
pub(crate) const ID_AUTH_RESERVED3_BYTES: usize = 0xFFF - 0xC84 + 1;

pub(crate) const ECDSA_POINT_SIZE_BITS: usize = 576;
pub(crate) const ECDSA_POINT_SIZE_BYTES: usize = ECDSA_POINT_SIZE_BITS / 8;

pub(crate) const ECDSA_PUBKEY_RESERVED: usize = 0x403 - 0x94 + 1;
pub(crate) const ECDSA_SIG_RESERVED: usize = 0x1ff - 0x90 + 1;

/// Family-Id of the guest, provided by the guest owner and uninterpreted by the firmware.
#[repr(C)]
#[derive(Default, Serialize, Deserialize, Clone, Copy, Encode, Debug)]
pub struct FamilyId([u8; ID_BLK_ID_BYTES]);

impl FamilyId {
    /// Create a new Family Id with the provided data
    pub fn new(data: [u8; ID_BLK_ID_BYTES]) -> Self {
        Self(data)
    }
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
#[derive(Default, Serialize, Deserialize, Clone, Copy, Encode, Decode)]
pub struct SevEcdsaSig {
    r: Array<u8, ECDSA_POINT_SIZE_BYTES>,
    s: Array<u8, ECDSA_POINT_SIZE_BYTES>,
    reserved: Array<u8, ECDSA_SIG_RESERVED>,
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

        Ok(SevEcdsaSig {
            r: pad_r.try_into()?,
            s: pad_s.try_into()?,
            ..Default::default()
        })
    }
}

/// Data inside the SEV ECDSA key
#[repr(C)]
#[derive(Default, Serialize, Deserialize, Clone, Copy, Encode, Decode)]
pub struct SevEcdsaKeyData {
    /// QX component of the ECDSA public key
    pub qx: Array<u8, ECDSA_POINT_SIZE_BYTES>,
    /// QY component of the ECDSA public key
    pub qy: Array<u8, ECDSA_POINT_SIZE_BYTES>,
    /// Reserved
    reserved: Array<u8, ECDSA_PUBKEY_RESERVED>,
}

/// SEV ECDSA public key. Need it in this format to calculate the AUTH-ID.
#[derive(Default, Serialize, Deserialize, Clone, Copy, Encode, Decode)]
pub struct SevEcdsaPubKey {
    /// curve type for the public key (defaults to P384)
    pub curve: u32,
    /// public key data
    pub data: SevEcdsaKeyData,
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

        let key_data = SevEcdsaKeyData {
            qx: pad_x.try_into()?,
            qy: pad_y.try_into()?,
            ..Default::default()
        };

        sev_key.data = key_data;

        Ok(sev_key)
    }
}

/// SEV-SNP ID-BLOCK
#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Copy, Encode, Debug)]
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

impl IdBlock {
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
#[derive(Serialize, Deserialize, Clone, Copy, Decode, Encode)]
///ID Authentication Information Structure
pub struct IdAuth {
    /// The algorithm of the ID Key. Defaults to P-384
    pub id_key_algo: u32,
    /// The algorithm of the Author Key. Defaults to P-384
    pub author_key_algo: u32,
    /// Reserved
    reserved1: Array<u8, ID_AUTH_RESERVED1_BYTES>,
    /// The signature of all bytes of the ID block
    pub id_block_sig: SevEcdsaSig,
    /// The public component of the ID key
    pub id_pubkey: SevEcdsaPubKey,
    /// Reserved
    reserved2: Array<u8, ID_AUTH_RESERVED2_BYTES>,
    /// The signature of the ID_KEY
    pub id_key_sig: SevEcdsaSig,
    /// The public component of the Author key
    pub author_pub_key: SevEcdsaPubKey,
    /// Reserved
    reserved3: Array<u8, ID_AUTH_RESERVED3_BYTES>,
}

impl IdAuth {
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

        Self {
            id_key_algo: id_algo,
            author_key_algo: key_algo,
            reserved1: Default::default(),
            id_block_sig,
            id_pubkey,
            reserved2: Default::default(),
            id_key_sig,
            author_pub_key,
            reserved3: Default::default(),
        }
    }
}

impl Default for IdAuth {
    fn default() -> Self {
        Self {
            id_key_algo: DEFAULT_KEY_ALGO,
            author_key_algo: DEFAULT_KEY_ALGO,
            reserved1: Default::default(),
            id_block_sig: Default::default(),
            id_pubkey: Default::default(),
            reserved2: Default::default(),
            id_key_sig: Default::default(),
            author_pub_key: Default::default(),
            reserved3: Default::default(),
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
