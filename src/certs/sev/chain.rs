// SPDX-License-Identifier: Apache-2.0

//! Utilities for operating on entire certificate chains.

use serde::{Deserialize, Serialize};

use super::*;

/// A complete certificate chain.
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Chain {
    /// The Certificate Authority chain.
    pub ca: ca::Chain,

    /// The SEV platform chain.
    pub sev: sev::Chain,
}

impl codicon::Decoder<()> for Chain {
    type Error = Error;

    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        let sev = sev::Chain::decode(&mut reader, ())?;
        let ca = ca::Chain::decode(&mut reader, ())?;
        Ok(Self { ca, sev })
    }
}

impl codicon::Encoder<()> for Chain {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> Result<()> {
        self.sev.encode(&mut writer, ())?;
        self.ca.encode(&mut writer, ())
    }
}

#[cfg(feature = "openssl")]
impl<'a> Verifiable for &'a Chain {
    type Output = &'a sev::Certificate;

    fn verify(self) -> Result<Self::Output> {
        let ask = self.ca.verify()?;
        (ask, &self.sev.cek).verify()?;
        self.sev.verify()
    }
}
