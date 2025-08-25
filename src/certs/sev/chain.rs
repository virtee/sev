// SPDX-License-Identifier: Apache-2.0

//! Utilities for operating on entire certificate chains.

use super::*;

use serde::{Deserialize, Serialize};
// use std::result::Result;

/// A complete certificate chain.
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Chain {
    /// The Certificate Authority chain.
    pub ca: ca::Chain,

    /// The SEV platform chain.
    pub sev: sev::Chain,
}

impl Decoder<()> for Chain {
    fn decode(mut reader: &mut impl Read, _: ()) -> Result<Self> {
        let sev = sev::Chain::decode(&mut reader, ())?;
        let ca = ca::Chain::decode(&mut reader, ())?;
        Ok(Self { ca, sev })
    }
}

impl Encoder<()> for Chain {
    fn encode(&self, mut writer: &mut impl Write, _: ()) -> Result<()> {
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
