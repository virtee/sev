// SPDX-License-Identifier: Apache-2.0

//! Utilities for operating on entire certificate chains.

use super::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A complete certificate chain.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct Chain {
    /// The Certificate Authority chain.
    pub ca: ca::Chain,

    /// The SEV platform chain.
    pub sev: cert::Chain,
}

impl Decoder<()> for Chain {
    fn decode(mut reader: &mut impl Read, _: ()) -> Result<Self> {
        let sev = cert::Chain::decode(&mut reader, ())?;
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
