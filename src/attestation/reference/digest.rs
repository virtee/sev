// SPDX-License-Identifier: Apache-2.0

//! SHA-256 and SHA-384 digest helpers for reference value calculation.
//!
//! Thin wrappers over the active crypto backend (`crypto-openssl` or
//! `crypto-rust`). Reference modules call these instead of OpenSSL or `sha2`
//! directly so SNP/SEV measurement code stays backend-neutral.
//!
//! # Usage in this crate
//!
//! | Function | Typical callers | Output size |
//! |----------|-----------------|-------------|
//! | [`sha256`] | [`super::sev_hashes::SevHashes`] — kernel, initrd, cmdline entries | 32 bytes |
//! | [`sha384`] | [`crate::attestation::reference::snp::measurement`] — GCTX launch digest; [`crate::attestation::reference::snp::idblock::generate_key_digest`] — key digests | 48 bytes |
//!
//! # Features
//!
//! Exactly one of `crypto-openssl` or `crypto-rust` must be enabled.

#[cfg(feature = "crypto-openssl")]
use openssl::sha::{sha256 as openssl_sha256, sha384 as openssl_sha384};

/// Compute a SHA-256 digest of `data`.
///
/// Used when building OVMF **SEV-HASHES** table entries (kernel, initrd, and
/// cmdline hashes). Returns a fixed 32-byte array.
///
/// # Arguments
///
/// * `data` — message to hash (for example, entire kernel file contents).
///
/// # Example
///
/// ```ignore
/// use sev::attestation::reference::digest::sha256;
///
/// let hash = sha256(b"hello");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(feature = "crypto-openssl")]
    {
        openssl_sha256(data)
    }

    #[cfg(feature = "crypto-rust")]
    {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    #[cfg(not(any(feature = "crypto-openssl", feature = "crypto-rust")))]
    compile_error!("either \"crypto-openssl\" or \"crypto-rust\" must be enabled");
}

/// Compute a SHA-384 digest of `data`.
///
/// Used throughout SNP reference calculation:
///
/// * **GCTX updates** — hash each measured 4 KiB page and fold into the launch
///   digest ([`crate::attestation::reference::snp::measurement`]).
/// * **ID key digests** — `SHA-384(public_key_wire_bytes)` in
///   [`crate::attestation::reference::snp::idblock::generate_key_digest`].
///
/// Returns a fixed 48-byte array (same size as [`SnpLaunchDigest`](crate::types::snp::SnpLaunchDigest)).
///
/// # Arguments
///
/// * `data` — message to hash.
pub fn sha384(data: &[u8]) -> [u8; 48] {
    #[cfg(feature = "crypto-openssl")]
    {
        openssl_sha384(data)
    }

    #[cfg(feature = "crypto-rust")]
    {
        use sha2::Digest;
        let hash = sha2::Sha384::digest(data);
        let mut out = [0u8; 48];
        out.copy_from_slice(&hash);
        out
    }

    #[cfg(not(any(feature = "crypto-openssl", feature = "crypto-rust")))]
    compile_error!("either \"crypto-openssl\" or \"crypto-rust\" must be enabled");
}
