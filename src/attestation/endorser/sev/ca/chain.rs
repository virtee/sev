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

impl From<crate::types::shared::Generation> for Chain {
    fn from(generation: crate::types::shared::Generation) -> Self {
        let (ark, ask) = match generation {
            #[cfg(feature = "sev")]
            crate::types::shared::Generation::Naples => (
                super::super::builtin::naples::ARK,
                super::super::builtin::naples::ASK,
            ),
            #[cfg(feature = "sev")]
            crate::types::shared::Generation::Rome => (
                super::super::builtin::rome::ARK,
                super::super::builtin::rome::ASK,
            ),
            #[cfg(any(feature = "sev", feature = "snp"))]
            crate::types::shared::Generation::Milan => (
                super::super::builtin::milan::ARK,
                super::super::builtin::milan::ASK,
            ),
            #[cfg(any(feature = "sev", feature = "snp"))]
            crate::types::shared::Generation::Genoa => (
                super::super::builtin::genoa::ARK,
                super::super::builtin::genoa::ASK,
            ),
            #[cfg(any(feature = "sev", feature = "snp"))]
            crate::types::shared::Generation::Turin => (
                super::super::builtin::turin::ARK,
                super::super::builtin::turin::ASK,
            ),
            #[cfg(any(feature = "sev", feature = "snp"))]
            crate::types::shared::Generation::Venice => {
                panic!("Venice SEV CA chain is not yet implemented")
            }
        };

        Self {
            ask: Certificate::decode(&mut &*ask, ()).unwrap(),
            ark: Certificate::decode(&mut &*ark, ()).unwrap(),
        }
    }
}
