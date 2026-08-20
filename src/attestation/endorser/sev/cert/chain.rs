// SPDX-License-Identifier: Apache-2.0

//! For operating on the SEV platform certificate chain.

use super::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The SEV certificate chain.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq)]
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

impl Decoder<()> for Chain {
    fn decode(mut reader: &mut impl Read, _: ()) -> Result<Self> {
        let pdh = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&pdh)? != Usage::PDH {
            return Err(ErrorKind::InvalidInput)?;
        }

        let pek = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&pek)? != Usage::PEK {
            return Err(ErrorKind::InvalidInput)?;
        }

        let oca = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&oca)? != Usage::OCA {
            return Err(ErrorKind::InvalidInput)?;
        }

        let cek = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&cek)? != Usage::CEK {
            return Err(ErrorKind::InvalidInput)?;
        }

        Ok(Self { pdh, pek, oca, cek })
    }
}

impl Encoder<()> for Chain {
    fn encode(&self, mut writer: &mut impl Write, _: ()) -> Result<()> {
        self.pdh.encode(&mut writer, ())?;
        self.pek.encode(&mut writer, ())?;
        self.oca.encode(&mut writer, ())?;
        self.cek.encode(&mut writer, ())
    }
}

impl TryFrom<&Chain> for crate::types::shared::Generation {
    type Error = ();

    fn try_from(schain: &Chain) -> std::result::Result<Self, Self::Error> {
        use crate::attestation::verifier::Verifiable;

        let naples: super::super::ca::Chain = crate::types::shared::Generation::Naples.into();
        let rome: super::super::ca::Chain = crate::types::shared::Generation::Rome.into();
        let milan: super::super::ca::Chain = crate::types::shared::Generation::Milan.into();
        let genoa: super::super::ca::Chain = crate::types::shared::Generation::Genoa.into();
        let turin: super::super::ca::Chain = crate::types::shared::Generation::Turin.into();

        Ok(if (&naples.ask, &schain.cek).verify().is_ok() {
            crate::types::shared::Generation::Naples
        } else if (&rome.ask, &schain.cek).verify().is_ok() {
            crate::types::shared::Generation::Rome
        } else if (&milan.ask, &schain.cek).verify().is_ok() {
            crate::types::shared::Generation::Milan
        } else if (&genoa.ask, &schain.cek).verify().is_ok() {
            crate::types::shared::Generation::Genoa
        } else if (&turin.ask, &schain.cek).verify().is_ok() {
            crate::types::shared::Generation::Turin
        } else {
            return Err(());
        })
    }
}
