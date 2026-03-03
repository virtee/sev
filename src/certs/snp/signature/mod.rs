// SPDX-License-Identifier: Apache-2.0

use std::{
    convert::TryFrom,
    fmt::Display,
    io::{Read, Write},
};

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use std::io::Error;

use crate::{
    parser::{Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use crate::certs::snp::Certificate;

/// ECDSA algorithm signature
pub mod ecdsa;

/// Signature algorithms that firmware may use to sign the SEV-SNP attestation report.
///
/// The algorithm identifier is encoded in the report body and is therefore derived
/// from **untrusted bytes**. It MUST NOT be treated as a trust signal on its own.
/// Authenticity is only established by successfully verifying the report signature.
///
/// This enum is intentionally explicit: unknown values are rejected during decoding.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignatureAlgorithm {
    /// ECDSA with SECP384R1 curve
    EcdsaSecp384r1 = 1,
}

/// Creates a [`SignatureAlgorithm`] from the numeric algorithm identifier encoded
/// in the report body.
///
/// # Errors
///
/// Returns `InvalidData` if `v` does not correspond to a supported algorithm.
impl TryFrom<u32> for SignatureAlgorithm {
    type Error = std::io::Error;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(SignatureAlgorithm::EcdsaSecp384r1),
            v => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unsupported signature algorithm: {}", v),
            )),
        }
    }
}

impl SignatureAlgorithm {
    /// Verify the report signature over `body` using `vek` and this algorithm.
    ///
    /// This validates the signature bytes against the signed body bytes; it does
    /// not parse or validate any fields inside the body.
    #[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
    pub fn verify(
        &self,
        body: &[u8],
        signature: &[u8],
        vek: &Certificate,
    ) -> Result<(), std::io::Error> {
        match self {
            SignatureAlgorithm::EcdsaSecp384r1 => {
                ecdsa::verify_ecdsa_signature(body, signature, vek)
            }
        }
    }
}

impl Encoder<()> for SignatureAlgorithm {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        match self {
            SignatureAlgorithm::EcdsaSecp384r1 => writer.write_bytes(1u32, ())?,
        };
        Ok(())
    }
}

impl Decoder<()> for SignatureAlgorithm {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let algo: u32 = reader.read_bytes()?;
        Self::try_from(algo)
    }
}

impl Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureAlgorithm::EcdsaSecp384r1 => write!(f, "ECDSA with SECP384R1"),
        }
    }
}
