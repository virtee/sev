// SPDX-License-Identifier: Apache-2.0

//! Everything needed for working with AMD SEV certificate chains.

pub mod builtin;
pub mod ca;
mod chain;

#[allow(clippy::module_inception)]
pub mod sev;

#[cfg(feature = "openssl")]
mod util;

#[cfg(feature = "openssl")]
mod crypto;

pub use chain::Chain;

use crate::util::*;
#[cfg(feature = "openssl")]
use util::*;

use std::{
    convert::*,
    io::{Error, ErrorKind, Read, Result, Write},
};

#[cfg(feature = "openssl")]
use openssl::*;

#[cfg(feature = "openssl")]
struct Body;

#[cfg(feature = "openssl")]
/// An interface for types that may contain entities such as
/// signatures that must be verified.
pub trait Verifiable {
    /// An output type for successful verification.
    type Output;

    /// Self-verifies signatures.
    fn verify(self) -> Result<Self::Output>;
}

#[cfg(feature = "openssl")]
/// An interface for types that can sign another type (i.e., a certificate).
pub trait Signer<T> {
    /// The now-signed type.
    type Output;

    /// Signs the target.
    fn sign(&self, target: &mut T) -> Result<Self::Output>;
}

#[cfg(feature = "openssl")]
struct Signature {
    id: Option<[u8; 16]>,
    sig: Vec<u8>,
    kind: pkey::Id,
    hash: hash::MessageDigest,
    usage: Usage,
}

#[cfg(feature = "openssl")]
/// Represents a private key.
pub struct PrivateKey<U> {
    id: Option<[u8; 16]>,
    key: pkey::PKey<pkey::Private>,
    hash: hash::MessageDigest,
    usage: U,
}

#[cfg(feature = "openssl")]
struct PublicKey<U> {
    id: Option<[u8; 16]>,
    key: pkey::PKey<pkey::Public>,
    hash: hash::MessageDigest,
    usage: U,
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
