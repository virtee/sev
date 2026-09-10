// SPDX-License-Identifier: Apache-2.0

//! SNP ID block and AUTH block reference value calculation.
//!
//! This module helps **guest owners** produce the launch-time ID block material
//! required by the SNP firmware. The output values are **reference values** you
//! compute offline and later compare against attestation report fields or pass
//! into launch ioctls — they are not verified here.
//!
//! # ID block flow
//!
//! SNP launch binds a guest to owner-chosen identity and signing keys through
//! two firmware-facing blobs:
//!
//! | Blob | Wire type | Role |
//! |------|-----------|------|
//! | ID block | [`IdBlock`](crate::types::snp::IdBlock) | Expected guest measurement and owner metadata |
//! | AUTH block | [`IdAuth`](crate::types::snp::IdAuth) | ECDSA signatures and public keys that authenticate the ID block |
//!
//! Two EC P-384 private keys are involved:
//!
//! - **ID key** — signs the serialized ID block bytes.
//! - **Author key** — signs the serialized ID public key bytes (delegating trust
//!   from the author to the ID key).
//!
//! Firmware also expects **key digests**: SHA-384 hashes of each public key's
//! wire encoding ([`SnpLaunchDigest`](crate::types::snp::SnpLaunchDigest)).
//!
//! ```text
//!  launch digest ──► IdBlock ──sign(ID key)──► id_block_sig
//!                       │                           │
//!                       │                      id_pubkey
//!                       │                           │
//!                       │                    sign(Author key)
//!                       │                           │
//!                       │                      id_key_sig + author_pub_key
//!                       ▼
//!                 IdAuth (AUTH block)
//!
//!  ID key  ──► SHA-384(pubkey bytes) ──► id_key_digest
//!  Author key ──► SHA-384(pubkey bytes) ──► auth_key_digest
//! ```
//!
//! Wire layouts for [`IdBlock`](crate::types::snp::IdBlock),
//! [`IdAuth`](crate::types::snp::IdAuth), [`SevEcdsaPubKey`](crate::types::snp::SevEcdsaPubKey),
//! and [`SevEcdsaSig`](crate::types::snp::SevEcdsaSig) live in
//! [`crate::types::snp`]. This module performs the OpenSSL-backed signing and
//! digest steps needed to populate those types.
//!
//! # Terminology
//!
//! [`IdBlock::launch_digest`](crate::types::snp::IdBlock::launch_digest) holds
//! the **expected measurement** produced by
//! [`super::snp_calc_launch_digest`](crate::attestation::reference::snp::snp_calc_launch_digest)
//! or [`super::calc_snp_ovmf_hash`](crate::attestation::reference::snp::calc_snp_ovmf_hash).
//! After guest boot, compare it to
//! [`ReportBody::measurement`](crate::attestation::evidence::snp::ReportBody::measurement)
//! in a verified attestation report.
//!
//! # Typical workflow
//!
//! 1. Compute the guest **launch digest** with
//!    [`crate::attestation::reference::snp::measurement`] (GCTX over OVMF,
//!    kernel, and vCPU state).
//! 2. Call [`snp_calculate_id`] with the launch digest, optional ID block field
//!    overrides, and paths to PEM/DER EC P-384 key files.
//! 3. Serialize [`IdMeasurements::id_block`] and [`IdMeasurements::id_auth`]
//!    with [`ByteParser::to_bytes`](crate::parser::ByteParser) and supply them
//!    at guest launch. Retain the key digests for policy configuration and
//!    later attestation comparison.
//!
//! ```ignore
//! use sev::{
//!     attestation::reference::snp::{
//!         idblock::snp_calculate_id,
//!         measurement::calc_snp_ovmf_hash,
//!     },
//!     parser::ByteParser,
//! };
//! use std::path::PathBuf;
//!
//! let launch_digest = calc_snp_ovmf_hash(PathBuf::from("OVMF.fd"))?;
//! let m = snp_calculate_id(
//!     Some(launch_digest),
//!     None, // family_id — zero when omitted
//!     None, // image_id
//!     None, // guest_svn
//!     None, // policy — defaults to [`DEFAULT_ID_POLICY`](crate::types::snp::DEFAULT_ID_POLICY)
//!     PathBuf::from("id-key.pem"),
//!     PathBuf::from("author-key.pem"),
//! )?;
//!
//! let id_block = m.id_block.to_bytes()?;
//! let id_auth = m.id_auth.to_bytes()?;
//! ```
//!
//! # Functions
//!
//! | Function | When to use |
//! |----------|-------------|
//! | [`snp_calculate_id`] | One-shot: ID block, AUTH block, and both key digests |
//! | [`gen_id_auth_block`] | AUTH block only, when the [`IdBlock`] is already built |
//! | [`generate_key_digest`] | Single key digest (ID or author) |
//! | [`load_priv_key`] | Load and validate a P-384 key for custom signing steps |
//!
//! # Internal modules
//!
//! | Module | Role |
//! |--------|------|
//! | `crypto` | OpenSSL ECDSA signing and public-key wire encoding for [`SevEcdsaSig`] / [`SevEcdsaPubKey`] |
//!
//! # Features
//!
//! Requires the `crypto-openssl` and `reference` features. Private keys must be
//! unencrypted EC P-384 (SECP384R1) in PEM or DER form.
//!
//! # Errors
//!
//! Operations return [`IdBlockError`](crate::error::IdBlockError) on I/O,
//! OpenSSL, or wire-format failures (for example, a non-P-384 key).

#[cfg(feature = "crypto-openssl")]
mod crypto;

use openssl::{ec::EcKey, nid::Nid, pkey::Private, sha::sha384};
use std::{convert::TryFrom, fs::File, io::Read, path::PathBuf};

use crate::{
    error::IdBlockError,
    parser::ByteParser,
    types::snp::{
        FamilyId, GuestPolicy, IdAuth, IdBlock, ImageId, SevEcdsaPubKey, SevEcdsaSig,
        SnpLaunchDigest,
    },
};

/// Complete set of ID block material produced for SNP guest launch.
///
/// Contains every value commonly needed when configuring a launch or recording
/// owner reference values for later attestation comparison.
#[derive(Default)]
pub struct IdMeasurements {
    /// Expected guest measurement ([`IdBlock::launch_digest`](crate::types::snp::IdBlock::launch_digest)).
    ///
    /// Populate from [`super::snp_calc_launch_digest`](crate::attestation::reference::snp::snp_calc_launch_digest).
    /// Serialize with [`ByteParser::to_bytes`](crate::parser::ByteParser) for
    /// the firmware ID block field.
    pub id_block: IdBlock,
    /// Authentication block binding the ID block to the ID and author keys.
    ///
    /// Holds [`IdAuth::id_block_sig`] (ID key over the ID block),
    /// [`IdAuth::id_key_sig`] (author key over the ID public key), and both
    /// public keys. Serialize with [`ByteParser::to_bytes`](crate::parser::ByteParser).
    pub id_auth: IdAuth,
    /// SHA-384 digest of the ID key public key wire bytes.
    ///
    /// Same size as [`SnpLaunchDigest`] (48 bytes). Often embedded in guest
    /// policy or compared against [`ReportBody::id_key_digest`](crate::attestation::evidence::snp::ReportBody::id_key_digest)
    /// after attestation.
    pub id_key_digest: SnpLaunchDigest,
    /// SHA-384 digest of the author key public key wire bytes.
    ///
    /// Same size as [`SnpLaunchDigest`] (48 bytes). Often compared against
    /// [`ReportBody::author_key_digest`](crate::attestation::evidence::snp::ReportBody::author_key_digest)
    /// after attestation.
    pub auth_key_digest: SnpLaunchDigest,
}

/// Build an AUTH block from an ID block and two EC P-384 private key files.
///
/// Use this when you already have an [`IdBlock`] (for example, one built with
/// [`IdBlock::new`](crate::types::snp::IdBlock::new)) and only need the paired
/// [`IdAuth`]. For the full launch set, prefer [`snp_calculate_id`].
///
/// # Signing steps
///
/// 1. Load the **ID key** from `id_key_file` and derive its [`SevEcdsaPubKey`].
/// 2. Sign `id_block.to_bytes()` with the ID key → [`IdAuth::id_block_sig`].
/// 3. Load the **author key** from `author_key_file` and derive its [`SevEcdsaPubKey`].
/// 4. Sign the ID public key wire bytes with the author key → [`IdAuth::id_key_sig`].
///
/// Algorithm fields in the returned [`IdAuth`] default to
/// [`DEFAULT_KEY_ALGO`](crate::types::snp::DEFAULT_KEY_ALGO) (ECDSA P-384).
///
/// # Arguments
///
/// * `id_block` — ID block whose serialized bytes are signed by the ID key.
/// * `id_key_file` — path to the ID private key (PEM or DER, EC P-384).
/// * `author_key_file` — path to the author private key (PEM or DER, EC P-384).
///
/// # Returns
///
/// A populated [`IdAuth`] ready to serialize with
/// [`ByteParser::to_bytes`](crate::parser::ByteParser).
///
/// # Errors
///
/// Returns [`IdBlockError`](crate::error::IdBlockError) if a key file cannot be
/// read, a key is not P-384, ID block serialization fails, or OpenSSL signing
/// fails.
///
/// # Example
///
/// ```ignore
/// use sev::{
///     attestation::reference::snp::idblock::gen_id_auth_block,
///     parser::ByteParser,
///     types::snp::IdBlock,
/// };
/// use std::path::PathBuf;
///
/// let id_block = IdBlock::default();
/// let id_auth = gen_id_auth_block(
///     &id_block,
///     PathBuf::from("id-key.pem"),
///     PathBuf::from("author-key.pem"),
/// )?;
/// let auth_bytes = id_auth.to_bytes()?;
/// ```
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

/// Load an EC P-384 private key from a PEM or DER file.
///
/// Lower-level helper used by the other functions in this module. Call this
/// directly when you need an OpenSSL [`EcKey`] for custom signing outside
/// [`gen_id_auth_block`] or [`snp_calculate_id`].
///
/// # Arguments
///
/// * `path` — filesystem path to the private key file.
///
/// # Returns
///
/// An OpenSSL EC private key on the SECP384R1 curve.
///
/// # Key format
///
/// Supported PEM headers:
/// - `-----BEGIN PRIVATE KEY-----` (PKCS#8)
/// - `-----BEGIN EC PRIVATE KEY-----` (legacy EC)
///
/// Files without a recognized PEM prefix are parsed as DER. Encrypted PEM keys
/// are not supported.
///
/// # Errors
///
/// * [`IdBlockError::FileError`](crate::error::IdBlockError::FileError) — file
///   not found or unreadable.
/// * [`IdBlockError::CryptoErrorStack`](crate::error::IdBlockError::CryptoErrorStack) —
///   invalid PEM/DER or key validation failure.
/// * [`IdBlockError::SevCurveError`](crate::error::IdBlockError::SevCurveError) —
///   key is not on SECP384R1.
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
        if name != Nid::SECP384R1 {
            return Err(IdBlockError::SevCurveError());
        };
    };

    Ok(pkey)
}

/// Compute the SHA-384 digest of a private key's public key wire bytes.
///
/// Produces the 48-byte digest firmware and attestation reports use for either
/// the ID key or the author key. The computation is:
///
/// ```text
/// SHA-384( SevEcdsaPubKey::to_bytes() )
/// ```
///
/// where the public key is derived from the private key at `key_path`.
///
/// # Arguments
///
/// * `key_path` — path to an EC P-384 private key ([`load_priv_key`]).
///
/// # Returns
///
/// A [`SnpLaunchDigest`] suitable for guest policy fields or comparison against
/// [`ReportBody::id_key_digest`](crate::attestation::evidence::snp::ReportBody::id_key_digest)
/// / [`ReportBody::author_key_digest`](crate::attestation::evidence::snp::ReportBody::author_key_digest).
///
/// # Errors
///
/// Same key-loading and encoding errors as [`load_priv_key`].
pub fn generate_key_digest(key_path: PathBuf) -> Result<SnpLaunchDigest, IdBlockError> {
    let ec_key = load_priv_key(key_path)?;

    let pub_key = SevEcdsaPubKey::try_from(&ec_key)?;

    Ok(SnpLaunchDigest::new(sha384(pub_key.to_bytes()?.as_slice())))
}

/// Primary entry point: build ID block, AUTH block, and both key digests.
///
/// Equivalent to calling [`IdBlock::new`](crate::types::snp::IdBlock::new),
/// [`gen_id_auth_block`], and [`generate_key_digest`] for each key file.
///
/// # Arguments
///
/// | Parameter | `None` default | Sets |
/// |-----------|----------------|------|
/// | `ld` | zero launch digest | [`IdBlock::launch_digest`] — usually from [`measurement`](crate::attestation::reference::snp::measurement) |
/// | `family_id` | zero | [`IdBlock::family_id`] |
/// | `image_id` | zero | [`IdBlock::image_id`] |
/// | `svn` | `0` | [`IdBlock::guest_svn`] |
/// | `policy` | [`DEFAULT_ID_POLICY`](crate::types::snp::DEFAULT_ID_POLICY) | [`IdBlock::policy`] |
/// | `id_key_file` | — | ID private key (required) |
/// | `auth_key_file` | — | author private key (required) |
///
/// # Returns
///
/// [`IdMeasurements`] containing:
///
/// - [`IdMeasurements::id_block`] — 96-byte ID block wire value
/// - [`IdMeasurements::id_auth`] — 4096-byte AUTH block wire value
/// - [`IdMeasurements::id_key_digest`] — SHA-384 of the ID public key
/// - [`IdMeasurements::auth_key_digest`] — SHA-384 of the author public key
///
/// Serialize the blocks with [`ByteParser::to_bytes`](crate::parser::ByteParser)
/// before passing them to launch firmware.
///
/// # Errors
///
/// Returns [`IdBlockError`](crate::error::IdBlockError) if ID block construction,
/// key loading, signing, or digest calculation fails.
///
/// # Example
///
/// See the [module-level example](crate::attestation::reference::snp::idblock).
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
