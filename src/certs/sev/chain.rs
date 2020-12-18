// SPDX-License-Identifier: Apache-2.0

//! For operating on the SEV platform certificate chain.

use serde::{Deserialize, Serialize};

use super::*;

/// The SEV certificate chain.
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Chain {
    /// The Platform Diffie-Hellman certificate.
    pub pdh: Certificate,

    /// The certificate for the PEK.
    pub pek: Certificate,

    /// The certificate for the OCA.
    pub oca: Certificate,

    /// The certificate for the CEK.
    pub cek: Certificate,
}

impl codicon::Decoder<()> for Chain {
    type Error = Error;

    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        let pdh = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&pdh)? != Usage::PDH {
            return Err(ErrorKind::InvalidInput.into());
        }

        let pek = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&pek)? != Usage::PEK {
            return Err(ErrorKind::InvalidInput.into());
        }

        let oca = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&oca)? != Usage::OCA {
            return Err(ErrorKind::InvalidInput.into());
        }

        let cek = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&cek)? != Usage::CEK {
            return Err(ErrorKind::InvalidInput.into());
        }

        Ok(Self { pdh, pek, oca, cek })
    }
}

impl codicon::Encoder<()> for Chain {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> Result<()> {
        self.pdh.encode(&mut writer, ())?;
        self.pek.encode(&mut writer, ())?;
        self.oca.encode(&mut writer, ())?;
        self.cek.encode(&mut writer, ())
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for Chain {
    type Output = Certificate;

    fn verify(self) -> Result<Certificate> {
        (&self.oca, &self.oca).verify()?;
        (&self.oca, &self.pek).verify()?;
        (&self.cek, &self.pek).verify()?;
        (&self.pek, &self.pdh).verify()?;
        Ok(self.pdh)
    }
}
