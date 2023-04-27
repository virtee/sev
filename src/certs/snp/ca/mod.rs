// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Operations for a Certificate Authority (CA) chain.

/// A Certificate Authority (CA) chain.
#[derive(Clone, Debug)]
pub struct Chain {
    /// AMD Root Key certificate.
    pub ark: Certificate,

    /// AMD Signing Key certificate.
    pub ask: Certificate,
}

/// Verify if a CA chain's ARK is self-signed, along with if the ARK signs the ASK.
impl<'a> Verifiable for &'a Chain {
    type Output = &'a Certificate;

    fn verify(self) -> Result<Self::Output> {
        // Verify that ARK is self-signed.
        (&self.ark, &self.ark).verify()?;

        // Verify that ARK signs ASK.
        (&self.ark, &self.ask).verify()?;

        Ok(&self.ask)
    }
}

mod tests {
    #[test]
    fn milan_ca_chain_verifiable() {
        use crate::certs::snp::{builtin::milan, ca::*, Verifiable};

        let chain = Chain {
            ark: milan::ark().unwrap(),
            ask: milan::ask().unwrap(),
        };

        chain.verify().unwrap();
    }

    #[test]
    fn genoa_ca_chain_verifiable() {
        use crate::certs::snp::{builtin::genoa, ca::*, Verifiable};

        let chain = Chain {
            ark: genoa::ark().unwrap(),
            ask: genoa::ask().unwrap(),
        };

        chain.verify().unwrap();
    }
}
