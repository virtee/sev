// SPDX-License-Identifier: Apache-2.0

//! For operating on OCA certificate chains.

use super::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A complete OCA certificate chain.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct Chain {
    /// The AMD Signing Key certificate.
    pub ask: Certificate,

    /// The AMD Root Key certificate.
    pub ark: Certificate,
}

impl Decoder<()> for Chain {
    fn decode(mut reader: &mut impl Read, _: ()) -> Result<Self> {
        let ask = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&ask)? != Usage::ASK {
            return Err(ErrorKind::InvalidInput)?;
        }

        let ark = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&ark)? != Usage::ARK {
            return Err(ErrorKind::InvalidInput)?;
        }

        Ok(Self { ask, ark })
    }
}

impl Encoder<()> for Chain {
    fn encode(&self, mut writer: &mut impl Write, _: ()) -> Result<()> {
        self.ask.encode(&mut writer, ())?;
        self.ark.encode(&mut writer, ())
    }
}

#[cfg(feature = "openssl")]
impl<'a> Verifiable for &'a Chain {
    type Output = &'a Certificate;

    fn verify(self) -> Result<Self::Output> {
        (&self.ark, &self.ark).verify()?;
        (&self.ark, &self.ask).verify()?;
        Ok(&self.ask)
    }
}
