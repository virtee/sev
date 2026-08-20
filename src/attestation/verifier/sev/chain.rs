// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::sev::{ca, cert, Chain};
use crate::attestation::verifier::Verifiable;

use std::io::Result;

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
