// SPDX-License-Identifier: Apache-2.0

//! Platform SEV certificates and the PEK/PDH certificate chain.

mod chain;

pub(crate) mod v1;

pub use chain::Chain;
pub use v1::sig::ecdsa::Signature as EcdsaSignature;

use super::*;

/// Denotes the usage of a platform SEV certificate.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Usage(u32);

impl Usage {
    /// Owner Certificate Authority.
    pub const OCA: Usage = Usage(super::Usage::OCA.0);

    /// Chip Endorsement Key.
    pub const CEK: Usage = Usage(super::Usage::CEK.0);

    /// Platform Endorsement Key.
    pub const PEK: Usage = Usage(super::Usage::PEK.0);

    /// Platform Diffie-Hellman (PDH).
    pub const PDH: Usage = Usage(super::Usage::PDH.0);
}

impl TryFrom<super::Usage> for Usage {
    type Error = ();

    fn try_from(value: super::Usage) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            super::Usage::OCA => Usage::OCA,
            super::Usage::CEK => Usage::CEK,
            super::Usage::PEK => Usage::PEK,
            super::Usage::PDH => Usage::PDH,
            _ => return Err(()),
        })
    }
}

impl From<Usage> for super::Usage {
    fn from(value: Usage) -> Self {
        Self(value.0)
    }
}

impl PartialEq<super::Usage> for Usage {
    fn eq(&self, other: &super::Usage) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<Usage> for super::Usage {
    fn eq(&self, other: &Usage) -> bool {
        self.0 == other.0
    }
}

#[cfg(feature = "serde")]
use serde::{de, ser};
#[cfg(feature = "serde")]
use serde_bytes::{ByteBuf, Bytes};
#[cfg(feature = "serde")]
use std::mem::size_of;

/// An SEV certificate.
#[repr(C)]
#[derive(Copy, Clone)]
pub union Certificate {
    pub(crate) version: u32,
    v1: v1::Certificate,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.version() {
            1 => write!(f, "{:?}", unsafe { self.v1 }),
            v => write!(f, "Certificate {{ version: {v} }}"),
        }
    }
}

#[cfg(feature = "crypto-openssl")]
impl std::fmt::Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use std::fmt::Error;
        use Encoder;

        let key = PublicKey::try_from(self).or(Err(Error))?;

        let mut hsh = hash::Hasher::new(key.hash)?;

        self.encode(&mut hsh, Body).or(Err(Error))?;

        write!(
            f,
            "{} {} ",
            crate::attestation::endorser::sev::Usage::from(key.usage),
            key
        )?;
        for b in hsh.finish()?.iter() {
            write!(f, "{:02x}", *b)?;
        }

        Ok(())
    }
}

impl Eq for Certificate {}
impl PartialEq for Certificate {
    fn eq(&self, other: &Certificate) -> bool {
        if unsafe { self.version != other.version } {
            return false;
        }
        match self.version() {
            1 => unsafe { self.v1 == other.v1 },
            _ => false,
        }
    }
}

impl<U: Copy + Into<crate::attestation::endorser::sev::Usage>> PartialEq<U> for Certificate {
    fn eq(&self, other: &U) -> bool {
        if let Ok(a) = Usage::try_from(self) {
            return a == (*other).into();
        }

        false
    }
}

impl Decoder<()> for Certificate {
    fn decode(reader: &mut impl Read, params: ()) -> Result<Self> {
        Ok(match u32::from_le(reader.load()?) {
            1 => Certificate {
                v1: v1::Certificate::decode(reader, params)?,
            },
            _ => return Err(ErrorKind::InvalidData)?,
        })
    }
}

impl Encoder<()> for Certificate {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<()> {
        match self.version() {
            1 => unsafe { writer.save(&self.v1) },
            _ => Err(ErrorKind::InvalidInput)?,
        }
    }
}

#[cfg(feature = "crypto-openssl")]
impl Encoder<Body> for Certificate {
    fn encode(&self, writer: &mut impl Write, _: Body) -> Result<()> {
        match self.version() {
            1 => unsafe { writer.save(&self.v1.body) },
            _ => Err(ErrorKind::InvalidInput)?,
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> de::Deserialize<'de> for Certificate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        use Decoder;

        let bytes = ByteBuf::deserialize(deserializer)?;
        Self::decode(&mut bytes.as_slice(), ()).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl ser::Serialize for Certificate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use std::slice::from_raw_parts;

        let bytes = unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) };
        let bytes = Bytes::new(bytes);
        bytes.serialize(serializer)
    }
}

#[cfg(feature = "crypto-openssl")]
impl TryFrom<&Certificate> for [Option<Signature>; 2] {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        match value.version() {
            1 => Ok([
                unsafe { &value.v1.sigs[0] }.try_into()?,
                unsafe { &value.v1.sigs[1] }.try_into()?,
            ]),
            _ => Err(ErrorKind::InvalidInput)?,
        }
    }
}

impl TryFrom<&Certificate> for Usage {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        match value.version() {
            1 => Ok(unsafe { value.v1.body.data.key.usage }),
            _ => Err(ErrorKind::InvalidInput)?,
        }
    }
}

impl TryFrom<&Certificate> for crate::attestation::endorser::sev::Usage {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        Ok(Usage::try_from(value)?.into())
    }
}

#[cfg(feature = "crypto-openssl")]
impl TryFrom<&Certificate> for PublicKey<Usage> {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        match value.version() {
            1 => PublicKey::try_from(unsafe {
                &std::ptr::addr_of!(value.v1.body.data.key).read_unaligned()
            }),
            _ => Err(ErrorKind::InvalidInput)?,
        }
    }
}

#[cfg(feature = "crypto-openssl")]
impl Signer<Certificate> for PrivateKey<Usage> {
    type Output = ();

    fn sign(&self, target: &mut Certificate) -> Result<()> {
        match target.version() {
            1 => self.sign(unsafe { &mut target.v1 }),
            _ => Err(ErrorKind::InvalidInput)?,
        }
    }
}

impl Certificate {
    #[cfg(feature = "crypto-openssl")]
    /// Generates a private key and its public certificate.
    pub fn generate(usage: Usage) -> Result<(Self, PrivateKey<Usage>)> {
        let (crt, prv) = v1::Certificate::generate(usage)?;
        Ok((Certificate { v1: crt }, prv))
    }

    #[inline]
    fn version(&self) -> u32 {
        u32::from_le(unsafe { self.version })
    }
}
