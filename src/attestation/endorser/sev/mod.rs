// SPDX-License-Identifier: Apache-2.0

//! Everything needed for working with AMD SEV certificate chains.
//!
//! Platform PEK/PDH/CEK wire types and chains live in [`cert`](self::cert).
//! CA and built-in generation chains are in [`ca`](self::ca) and
//! [`builtin`](self::builtin).

pub mod builtin;
pub mod ca;
pub mod cert;
mod chain;

#[cfg(feature = "crypto-openssl")]
mod crypto;

pub use chain::Chain;

use crate::util::*;

#[cfg(feature = "crypto-openssl")]
use crate::util::openssl_helpers::*;

use crate::parser::{Decoder, Encoder};

use std::{
    convert::*,
    io::{Error, ErrorKind, Read, Result, Write},
};

#[cfg(feature = "crypto-openssl")]
use openssl::*;

/// OpenSSL body
#[cfg(feature = "crypto-openssl")]
pub(crate) struct Body;

#[cfg(feature = "crypto-openssl")]
/// An interface for types that can sign another type (i.e., a certificate).
pub trait Signer<T> {
    /// The now-signed type.
    type Output;

    /// Signs the target.
    fn sign(&self, target: &mut T) -> Result<Self::Output>;
}

/// OpenSSL related signature
#[cfg(feature = "crypto-openssl")]
pub(crate) struct Signature {
    id: Option<[u8; 16]>,
    sig: Vec<u8>,
    kind: pkey::Id,
    hash: hash::MessageDigest,
    usage: Usage,
}

#[cfg(feature = "crypto-openssl")]
/// Represents a private key.
pub struct PrivateKey<U> {
    id: Option<[u8; 16]>,
    key: pkey::PKey<pkey::Private>,
    hash: hash::MessageDigest,
    usage: U,
}

/// Represents a public key.
#[cfg(feature = "crypto-openssl")]
pub(crate) struct PublicKey<U> {
    id: Option<[u8; 16]>,
    key: pkey::PKey<pkey::Public>,
    hash: hash::MessageDigest,
    usage: U,
}

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
impl<U> PublicKey<U> {
    /// Obtains the OpenSSL EcKey<Public> within.
    pub fn ec_key(
        &self,
    ) -> std::result::Result<openssl::ec::EcKey<openssl::pkey::Public>, openssl::error::ErrorStack>
    {
        self.key.ec_key()
    }
}

/// Denotes a certificate's usage.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Usage(u32);

impl Usage {
    /// Owner Certificate Authority.
    pub const OCA: Usage = Usage(0x1001u32.to_le());

    /// AMD Root Key.
    pub const ARK: Usage = Usage(0x0000u32.to_le());

    /// AMD Signing Key.
    pub const ASK: Usage = Usage(0x0013u32.to_le());

    /// Chip Endorsement Key.
    pub const CEK: Usage = Usage(0x1004u32.to_le());

    /// Platform Endorsement Key.
    pub const PEK: Usage = Usage(0x1002u32.to_le());

    /// Platform Diffie-Hellman.
    pub const PDH: Usage = Usage(0x1003u32.to_le());

    const INV: Usage = Usage(0x1000u32.to_le());
}

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Usage::OCA => "OCA",
                Usage::PEK => "PEK",
                Usage::PDH => "PDH",
                Usage::CEK => "CEK",
                Usage::ARK => "ARK",
                Usage::ASK => "ASK",
                Usage::INV => "INV",
                _ => return Err(std::fmt::Error),
            }
        )
    }
}
