// SPDX-License-Identifier: Apache-2.0

//! Functions to use to calculate the ID-BLOCK and the AUTH-BLOCK.

use openssl::{ec::EcKey, pkey::Private, sha::sha384};
use std::{convert::TryFrom, fs::File, io::Read, path::PathBuf};

use crate::{
    error::IdBlockError,
    firmware::guest::GuestPolicy,
    measurement::{
        idblock_types::{
            FamilyId, IdAuth, IdBlock, IdMeasurements, ImageId, SevEcdsaPubKey, SevEcdsaSig,
            CURVE_P384_NID,
        },
        snp::SnpLaunchDigest,
    },
    parser::ByteParser,
};

/// Generate an AUTH-BLOCK using 2 EC P-384 keys and an already calculated ID-BlOCK
pub fn gen_id_auth_block(
    id_block: &IdBlock,
    id_key_file: PathBuf,
    author_key_file: PathBuf,
) -> Result<IdAuth, IdBlockError> {
    let id_ec_priv_key = load_priv_key(id_key_file)?;
    let id_ec_pub_key = SevEcdsaPubKey::try_from(&id_ec_priv_key)?;
    let serialized_id_block = id_block.to_bytes()?;
    let id_sig = SevEcdsaSig::try_from((id_ec_priv_key, serialized_id_block.as_slice()))?;

    let author_ec_priv_key = load_priv_key(author_key_file)?;
    let author_pub_key = SevEcdsaPubKey::try_from(&author_ec_priv_key)?;
    let author_sig =
        SevEcdsaSig::try_from((author_ec_priv_key, id_ec_pub_key.to_bytes()?.as_slice()))?;

    Ok(IdAuth::new(
        None,
        None,
        id_sig,
        id_ec_pub_key,
        author_sig,
        author_pub_key,
    ))
}

enum KeyFormat {
    Pem,
    Der,
}

const PEM_PREFIXES: &[&[u8]] = &[
    b"-----BEGIN PRIVATE KEY-----",           // PKCS8
    b"-----BEGIN EC PRIVATE KEY-----",        // legacy EC
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----", // encrypted PKCS8
];

/// Identifies the format of a key based on the first line specified
/// for the PEM. A non-PEM format assumes a DER format.
fn identify_priv_key_format(bytes: &[u8]) -> KeyFormat {
    if PEM_PREFIXES.iter().any(|prefix| bytes.starts_with(prefix)) {
        KeyFormat::Pem
    } else {
        KeyFormat::Der
    }
}
///Read a key file and return a private EcKey.
/// Key has to be an EC P-384 key.
pub fn load_priv_key(path: PathBuf) -> Result<EcKey<Private>, IdBlockError> {
    let mut key_data = Vec::new();
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => return Err(IdBlockError::FileError(e)),
    };

    file.read_to_end(&mut key_data)
        .map_err(IdBlockError::FileError)?;

    let pkey = match identify_priv_key_format(&key_data) {
        KeyFormat::Pem => {
            EcKey::private_key_from_pem(&key_data).map_err(IdBlockError::CryptoErrorStack)?
        }
        KeyFormat::Der => {
            EcKey::private_key_from_der(&key_data).map_err(IdBlockError::CryptoErrorStack)?
        }
    };

    pkey.check_key().map_err(IdBlockError::CryptoErrorStack)?;

    if let Some(name) = pkey.group().curve_name() {
        if name != CURVE_P384_NID {
            return Err(IdBlockError::SevCurveError());
        };
    };

    Ok(pkey)
}

/// Generate the sha384 digest of the provided pem key (same sized digest as SNP Launch Digest)
pub fn generate_key_digest(key_path: PathBuf) -> Result<SnpLaunchDigest, IdBlockError> {
    let ec_key = load_priv_key(key_path)?;

    let pub_key = SevEcdsaPubKey::try_from(&ec_key)?;

    Ok(SnpLaunchDigest::new(sha384(pub_key.to_bytes()?.as_slice())))
}

/// Calculate the different pieces needed for a complete pre-attestation.
/// ID-BLOCK, AUTH-BLOCK, id-key digest and auth-key digest.
pub fn snp_calculate_id(
    ld: Option<SnpLaunchDigest>,
    family_id: Option<FamilyId>,
    image_id: Option<ImageId>,
    svn: Option<u32>,
    policy: Option<GuestPolicy>,
    id_key_file: PathBuf,
    auth_key_file: PathBuf,
) -> Result<IdMeasurements, IdBlockError> {
    let id_block = IdBlock::new(ld, family_id, image_id, svn, policy)?;

    Ok(IdMeasurements {
        id_block,
        id_auth: gen_id_auth_block(&id_block, id_key_file.clone(), auth_key_file.clone())?,

        id_key_digest: generate_key_digest(id_key_file)?,

        auth_key_digest: generate_key_digest(auth_key_file)?,
    })
}
