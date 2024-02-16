// SPDX-License-Identifier: Apache-2.0

use super::*;

use crate::error::CertFormatError;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;

/// Structures/interfaces for SEV-SNP certificates.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate(X509);

#[derive(Clone, Copy, Debug)]
enum CertFormat {
    Pem,
    Der,
}

impl ToString for CertFormat {
    fn to_string(&self) -> String {
        match self {
            Self::Pem => "pem",
            Self::Der => "der",
        }
        .to_string()
    }
}

impl std::str::FromStr for CertFormat {
    type Err = CertFormatError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pem" => Ok(Self::Pem),
            "der" => Ok(Self::Der),
            _ => Err(CertFormatError::UnknownFormat),
        }
    }
}

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

    /// Serialize a Certificate struct to PEM.
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_pem()?)
    }

    /// Create a Certificate from a DER-encoded X509 structure.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Ok(Self(X509::from_der(der)?))
    }

    /// Serialize a Certificate struct to DER.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_der()?)
    }

    /// Retrieve the underlying X509 public key for a Certificate.
    pub fn public_key(&self) -> Result<PKey<Public>> {
        Ok(self.0.public_key()?)
    }

    /// Identifies the format of a certificate based upon the first twenty-eight
    /// bytes of a byte stream. A non-PEM format assumes DER format.
    fn identify_format(bytes: &[u8]) -> CertFormat {
        const PEM_START: &[u8] = b"-----BEGIN CERTIFICATE-----";
        match bytes {
            PEM_START => CertFormat::Pem,
            _ => CertFormat::Der,
        }
    }

    /// An façade method for constructing a Certificate from raw bytes.
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<Self> {
        match Self::identify_format(raw_bytes) {
            CertFormat::Pem => Self::from_pem(raw_bytes),
            CertFormat::Der => Self::from_der(raw_bytes),
        }
    }
}
