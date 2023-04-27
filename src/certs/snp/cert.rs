// SPDX-License-Identifier: Apache-2.0

use super::*;

use openssl::pkey::{PKey, Public};

/// Structures/interfaces for SEV-SNP certificates.

#[derive(Clone, Debug)]
pub struct Certificate(X509);

/// Wrap an X509 struct into a Certificate.
impl From<X509> for Certificate {
    fn from(x509: X509) -> Self {
        Self(x509)
    }
}

/// Unwrap the underlying X509 struct from a Certificate.
impl From<Certificate> for X509 {
    fn from(cert: Certificate) -> Self {
        cert.0
    }
}

/// Clone the underlying X509 structure from a reference to a Certificate.
impl From<&Certificate> for X509 {
    fn from(cert: &Certificate) -> Self {
        cert.0.clone()
    }
}

/// Verify if the public key of one Certificate signs another Certificate.
impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<Self::Output> {
        let signer: X509 = self.0.into();
        let signee: X509 = self.1.into();

        let key: PKey<Public> = signer.public_key()?;
        let signed = signee.verify(&key)?;

        match signed {
            true => Ok(()),
            false => Err(Error::new(
                ErrorKind::Other,
                "Signer certificate does not sign signee certificate",
            )),
        }
    }
}

impl Certificate {
    /// Create a Certificate from a PEM-encoded X509 structure.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Ok(Self(X509::from_pem(pem)?))
    }

    /// Create a Certificate from a DER-encoded X509 structure.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Ok(Self(X509::from_der(der)?))
    }

    /// Retrieve the underlying X509 public key for a Certificate.
    pub fn public_key(&self) -> Result<PKey<Public>> {
        Ok(self.0.public_key()?)
    }
}
