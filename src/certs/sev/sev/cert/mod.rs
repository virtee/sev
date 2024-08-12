// SPDX-License-Identifier: Apache-2.0

//! Operations that can be done on an SEV certificate.

pub(crate) mod v1;

use super::*;

use std::mem::size_of;

use serde::{de, ser};
use serde_bytes::{ByteBuf, Bytes};

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

#[cfg(feature = "openssl")]
impl std::fmt::Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use codicon::Encoder;
        use std::fmt::Error;

        let key = PublicKey::try_from(self).or(Err(Error))?;

        let mut hsh = hash::Hasher::new(key.hash)?;

        self.encode(&mut hsh, Body).or(Err(Error))?;

        write!(f, "{} {} ", crate::certs::sev::Usage::from(key.usage), key)?;
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

impl<U: Copy + Into<crate::certs::sev::Usage>> PartialEq<U> for Certificate {
    fn eq(&self, other: &U) -> bool {
        if let Ok(a) = Usage::try_from(self) {
            return a == (*other).into();
        }

        false
    }
}

impl codicon::Decoder<()> for Certificate {
    type Error = Error;

    fn decode(mut reader: impl Read, params: ()) -> Result<Self> {
        Ok(match u32::from_le(reader.load()?) {
            1 => Certificate {
                v1: v1::Certificate::decode(reader, params)?,
            },
            _ => return Err(ErrorKind::InvalidData)?,
        })
    }
}

impl codicon::Encoder<()> for Certificate {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> Result<()> {
        match self.version() {
            1 => unsafe { writer.save(&self.v1) },
            _ => Err(ErrorKind::InvalidInput)?,
        }
    }
}

#[cfg(feature = "openssl")]
impl codicon::Encoder<Body> for Certificate {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: Body) -> Result<()> {
        match self.version() {
            1 => unsafe { writer.save(&self.v1.body) },
            _ => Err(ErrorKind::InvalidInput)?,
        }
    }
}

impl<'de> de::Deserialize<'de> for Certificate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        use codicon::Decoder;

        let bytes = ByteBuf::deserialize(deserializer)?;
        Self::decode(bytes.as_slice(), ()).map_err(serde::de::Error::custom)
    }
}

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

#[cfg(feature = "openssl")]
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

impl TryFrom<&Certificate> for crate::certs::sev::Usage {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        Ok(Usage::try_from(value)?.into())
    }
}

#[cfg(feature = "openssl")]
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

#[cfg(feature = "openssl")]
impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key = PublicKey::try_from(self.0)?;

        let sigs: [Option<Signature>; 2] = self.1.try_into()?;
        for sig in sigs.iter().flatten() {
            if key.verify(self.1, sig).is_ok() {
                return Ok(());
            }
        }

        Err(ErrorKind::InvalidInput)?
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for (&ca::Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key: PublicKey<ca::Usage> = self.0.try_into()?;

        let sigs: [Option<Signature>; 2] = self.1.try_into()?;
        for sig in sigs.iter().flatten() {
            if key.verify(self.1, sig).is_ok() {
                return Ok(());
            }
        }

        Err(ErrorKind::InvalidInput)?
    }
}

#[cfg(feature = "openssl")]
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
    #[cfg(feature = "openssl")]
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
