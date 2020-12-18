// SPDX-License-Identifier: Apache-2.0

//! For operating on OCA certificate chains.

use serde::{Deserialize, Serialize};

use super::*;

/// A complete OCA certificate chain.
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Chain {
    /// The AMD Signing Key certificate.
    pub ask: Certificate,

    /// The AMD Root Key certificate.
    pub ark: Certificate,
}

impl codicon::Decoder<()> for Chain {
    type Error = Error;

    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        let ask = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&ask)? != Usage::ASK {
            return Err(ErrorKind::InvalidInput.into());
        }

        let ark = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&ark)? != Usage::ARK {
            return Err(ErrorKind::InvalidInput.into());
        }

        Ok(Self { ask, ark })
    }
}

impl codicon::Encoder<()> for Chain {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> Result<()> {
        self.ask.encode(&mut writer, ())?;
        self.ark.encode(&mut writer, ())
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for Chain {
    type Output = Certificate;

    fn verify(self) -> Result<Certificate> {
        (&self.ark, &self.ark).verify()?;
        (&self.ark, &self.ask).verify()?;
        Ok(self.ask)
    }
}
