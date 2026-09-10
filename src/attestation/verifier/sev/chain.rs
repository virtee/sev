// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::sev::{ca, cert, Chain};
use crate::attestation::verifier::Verifiable;

use std::io::Result;

// Only `infer_generation` needs the generation table and its error path.
#[cfg(all(feature = "dangerous_hw_tests", feature = "platform"))]
use crate::types::shared::Generation;
#[cfg(all(feature = "dangerous_hw_tests", feature = "platform"))]
use std::io::{Error, ErrorKind};

impl<'a> Verifiable for &'a ca::Chain {
    type Output = &'a ca::Certificate;

    fn verify(self) -> Result<Self::Output> {
        (&self.ark, &self.ark).verify()?;
        (&self.ark, &self.ask).verify()?;
        Ok(&self.ask)
    }
}

impl<'a> Verifiable for &'a cert::Chain {
    type Output = &'a cert::Certificate;

    fn verify(self) -> Result<Self::Output> {
        (&self.oca, &self.oca).verify()?;
        (&self.oca, &self.pek).verify()?;
        (&self.cek, &self.pek).verify()?;
        (&self.pek, &self.pdh).verify()?;
        Ok(&self.pdh)
    }
}

impl<'a> Verifiable for &'a Chain {
    type Output = &'a cert::Certificate;

    fn verify(self) -> Result<Self::Output> {
        let ask = self.ca.verify()?;
        (ask, &self.sev.cek).verify()?;
        self.sev.verify()
    }
}

/// Infers the platform generation by verifying the chain's CEK against each
/// built-in ASK, returning the generation whose ASK signed it.
///
/// Crate-internal: the only consumer is [`crate::util::cached_chain::get_chain`],
/// which assembles a full chain from an exported platform chain, so this is
/// gated on the same features that gate that helper.
///
/// This is a free function rather than a `TryFrom<&cert::Chain> for Generation`
/// impl because inferring the generation requires [`Verifiable`], which only
/// exists under the `verifier` feature; an impl would silently vanish for
/// `endorser`-only builds and fail at the call site with an unsatisfied trait
/// bound on [`Generation`] instead of an unresolved path naming the module.
///
/// # Errors
///
/// Returns [`ErrorKind::InvalidData`] if no built-in ASK verifies the CEK,
/// which means the chain is not from a recognized AMD platform generation.
#[cfg(all(feature = "dangerous_hw_tests", feature = "platform"))]
pub(crate) fn infer_generation(schain: &cert::Chain) -> Result<Generation> {
    let naples: ca::Chain = Generation::Naples.into();
    let rome: ca::Chain = Generation::Rome.into();
    let milan: ca::Chain = Generation::Milan.into();
    let genoa: ca::Chain = Generation::Genoa.into();
    let turin: ca::Chain = Generation::Turin.into();

    Ok(if (&naples.ask, &schain.cek).verify().is_ok() {
        Generation::Naples
    } else if (&rome.ask, &schain.cek).verify().is_ok() {
        Generation::Rome
    } else if (&milan.ask, &schain.cek).verify().is_ok() {
        Generation::Milan
    } else if (&genoa.ask, &schain.cek).verify().is_ok() {
        Generation::Genoa
    } else if (&turin.ask, &schain.cek).verify().is_ok() {
        Generation::Turin
    } else {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "chain CEK was not signed by any known AMD generation ASK",
        ));
    })
}
