// SPDX-License-Identifier: Apache-2.0

mod ecdsa;

use crate::parser::{Decoder, Encoder};
use crate::util::parser_helper::{ReadExt, WriteExt};

use std::convert::TryFrom;
use std::fmt::Display;
use std::io::{self, Read, Write};

pub use ecdsa::Signature;

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

impl TryFrom<u32> for SignatureAlgorithm {
    type Error = std::io::Error;

    fn try_from(v: u32) -> io::Result<Self> {
        match v {
            1 => Ok(SignatureAlgorithm::EcdsaSecp384r1),
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported signature algorithm: {}", v),
            )),
        }
    }
}

impl Encoder<()> for SignatureAlgorithm {
    fn encode(&self, writer: &mut impl Write, _: ()) -> io::Result<()> {
        match self {
            SignatureAlgorithm::EcdsaSecp384r1 => writer.write_bytes(1u32, ())?,
        };
        Ok(())
    }
}

impl Decoder<()> for SignatureAlgorithm {
    fn decode(reader: &mut impl Read, _: ()) -> io::Result<Self> {
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
