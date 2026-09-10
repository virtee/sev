// SPDX-License-Identifier: Apache-2.0

//! X.509 certificate wrapper (pure-Rust `x509-cert` backend).
//!
//! Same public [`Certificate`] type name as the OpenSSL backend; this module is
//! compiled when `crypto-rust` is enabled instead of `crypto-openssl`.

use super::*;

use der::{Decode, DecodePem, Encode};
use std::io;
use std::io::ErrorKind;
use x509_cert::der;

/// SNP endorsement X.509 certificate (pure-Rust backend).
///
/// Parse with [`Self::from_pem`] or [`Self::from_der`]. Used as elements of
/// [`CaChain`](super::CaChain) and [`Chain`](super::Chain).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate(x509_cert::Certificate);

/// Wrap an X509 certificate into a Certificate.
impl From<x509_cert::Certificate> for Certificate {
    fn from(cert: x509_cert::Certificate) -> Self {
        Self(cert)
    }
}

/// Unwrap the underlying X509 certificate from a Certificate.
impl From<Certificate> for x509_cert::Certificate {
    fn from(cert: Certificate) -> Self {
        cert.0
    }
}

/// Clone the underlying X509 certificate from a reference to a Certificate.
impl From<&Certificate> for x509_cert::Certificate {
    fn from(cert: &Certificate) -> Self {
        cert.0.clone()
    }
}

impl From<&x509_cert::Certificate> for Certificate {
    fn from(value: &x509_cert::Certificate) -> Self {
        Self(value.clone())
    }
}

impl<'a: 'b, 'b> From<&'a Certificate> for &'b x509_cert::Certificate {
    fn from(value: &'a Certificate) -> Self {
        &value.0
    }
}

impl Certificate {
    /// Create a Certificate from a PEM-encoded X509 structure.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let cert = x509_cert::Certificate::from_pem(pem)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("invalid PEM: {}", e)))?;
        Ok(Self(cert))
    }

    /// Serialize a Certificate struct to PEM.
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        use der::EncodePem;
        Ok(self
            .0
            .to_pem(der::pem::LineEnding::default())
            .map_err(|e| io_error_other(format!("PEM-encoding failed: {}", e)))?
            .into_bytes())
    }

    /// Create a Certificate from a DER-encoded X509 structure.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let cert = x509_cert::Certificate::from_der(der)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("invalid DER: {}", e)))?;
        Ok(Self(cert))
    }

    /// Serialize a Certificate struct to DER.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.0
            .to_der()
            .map_err(|e| io_error_other(format!("DER-encoding failed: {e:?}")))
    }

    /// Retrieve the public key in SEC1 encoding.
    pub fn public_key_sec1(&self) -> &[u8] {
        self.0
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
    }
}

fn io_error_other<S: Into<String>>(error: S) -> io::Error {
    io::Error::new(ErrorKind::Other, error.into())
}
