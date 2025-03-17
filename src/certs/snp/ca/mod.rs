// SPDX-License-Identifier: Apache-2.0
//! Operations for a Certificate Authority (CA) chain.

#[cfg(feature = "openssl")]
use openssl::x509::X509;

use super::*;

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

#[cfg(feature = "openssl")]
impl From<(X509, X509)> for Chain {
    /// Assumes the structure of ASK/ARK or ASVK/ARK
    fn from(value: (X509, X509)) -> Self {
        Self {
            ark: value.1.into(),
            ask: value.0.into(),
        }
    }
}

#[cfg(feature = "openssl")]
impl From<(&X509, &X509)> for Chain {
    /// Assumes the structure of &ASK/&ARK or &ASVK/&ARK
    fn from(value: (&X509, &X509)) -> Self {
        (value.0.clone(), value.1.clone()).into()
    }
}

#[cfg(feature = "openssl")]
impl<'a: 'b, 'b> From<&'a Chain> for (&'b X509, &'b X509) {
    /// Will always assume the tuple type to be (&ASK, &ARK) or (&ASVK, &ARK).
    fn from(value: &'a Chain) -> Self {
        ((&value.ask).into(), (&value.ark).into())
    }
}

#[cfg(feature = "openssl")]
impl From<&[X509]> for Chain {
    /// Will only retrieve the first two certificates, ignoring the rest. Also
    /// assumes the structure to be (&ASK, &ARK) or (&ASVK, &ARK)
    fn from(value: &[X509]) -> Self {
        (&value[0], &value[1]).into()
    }
}

impl From<(Certificate, Certificate)> for Chain {
    /// Assumes the structure of ASK/ARK or ASVK/ARK
    fn from(value: (Certificate, Certificate)) -> Self {
        Self {
            ark: value.1,
            ask: value.0,
        }
    }
}

impl From<(&Certificate, &Certificate)> for Chain {
    /// Assumes the structure of &ASK/&ARK or &ASVK/&ARK
    fn from(value: (&Certificate, &Certificate)) -> Self {
        Self {
            ark: value.1.clone(),
            ask: value.0.clone(),
        }
    }
}

impl<'a: 'b, 'b> From<&'a Chain> for (&'b Certificate, &'b Certificate) {
    /// Will always assume the tuple type to be (&ASK, &ARK) or (&ASVK, &ARK).
    fn from(value: &'a Chain) -> Self {
        (&value.ask, &value.ark)
    }
}

impl From<&[Certificate]> for Chain {
    /// Will only retrieve the first two certificates, ignoring the rest. Also
    /// assumes the structure to be (&ASK, &ARK) or (&ASVK, &ARK)
    fn from(value: &[Certificate]) -> Self {
        (&value[0], &value[1]).into()
    }
}

impl Chain {
    /// Deserialize a PEM-encoded ARK and ASK pair to a CA chain.
    pub fn from_pem(ark: &[u8], ask: &[u8]) -> Result<Self> {
        Ok(Self {
            ark: Certificate::from_pem(ark)?,
            ask: Certificate::from_pem(ask)?,
        })
    }

    /// Deserialize a DER-encoded ARK and ASK pair to a CA chain.
    pub fn from_der(ark: &[u8], ask: &[u8]) -> Result<Self> {
        Ok(Self {
            ark: Certificate::from_der(ark)?,
            ask: Certificate::from_der(ask)?,
        })
    }

    #[cfg(feature = "openssl")]
    /// Deserialize the certificates from a PEM stack to a CA chain.
    pub fn from_pem_bytes(stack: &[u8]) -> Result<Self> {
        let certificates = X509::stack_from_pem(stack)?;
        let ark_cert = &certificates[1];
        let ask_cert = &certificates[0];
        Ok(Self {
            ark: ark_cert.into(),
            ask: ask_cert.into(),
        })
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
