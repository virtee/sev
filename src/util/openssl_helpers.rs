// SPDX-License-Identifier: Apache-2.0

//! OpenSSL byte-order helpers for AMD wire formats.
//!
//! AMD SEV and SEV-SNP firmware store big integers in **little-endian** byte
//! order inside fixed-size fields (for example, 72-byte ECDSA `r`/`s` scalars
//! or 512-byte RSA components). OpenSSL [`BigNum`](openssl::bn::BigNum) uses
//! big-endian internally, so these traits convert between the two conventions.
//!
//! Used by SNP report signature verification in
//! [`crate::attestation::verifier::snp::ecdsa`] (requires `verifier`, `snp`, and
//! `crypto-openssl`) and by legacy SEV certificate code in
//! [`crate::attestation::endorser::sev`] (requires `endorser`, `sev`, and
//! `crypto-openssl`).

use std::io::Result;

/// Construct a value from a little-endian byte slice.
///
/// For [`openssl::bn::BigNum`], reverses the input bytes before parsing so
/// firmware LE layout maps to OpenSSL's BE representation.
pub(crate) trait FromLe: Sized {
    /// Parse `value` as a little-endian integer.
    fn from_le(value: &[u8]) -> Result<Self>;
}

/// Serialize a value into a little-endian fixed-size byte array.
///
/// Implementations for [`openssl::bn::BigNumRef`] reverse OpenSSL's big-endian
/// output to match AMD's on-wire field layout.
pub(crate) trait AsLeBytes<T> {
    /// Write the value as little-endian bytes into type `T` (typically `[u8; N]`).
    fn as_le_bytes(&self) -> T;
}

impl FromLe for openssl::bn::BigNum {
    #[inline]
    fn from_le(value: &[u8]) -> Result<Self> {
        Ok(Self::from_slice(
            &value.iter().rev().cloned().collect::<Vec<_>>(),
        )?)
    }
}

impl AsLeBytes<[u8; 72]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 72] {
        let mut buf = [0u8; 72];

        for (i, b) in self.to_vec().into_iter().rev().enumerate() {
            buf[i] = b;
        }

        buf
    }
}

impl AsLeBytes<[u8; 512]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 512] {
        let mut buf = [0u8; 512];

        for (i, b) in self.to_vec().into_iter().rev().enumerate() {
            buf[i] = b;
        }

        buf
    }
}
