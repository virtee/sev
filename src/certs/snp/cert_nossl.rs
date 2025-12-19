// SPDX-License-Identifier: Apache-2.0

use super::*;

use der::{referenced::OwnedToRef, Decode, DecodePem, Encode};
use rsa::signature; // re-export of signature crate
use signature::Verifier;
use spki::ObjectIdentifier;
use std::convert::TryFrom;
use std::io;
use std::io::ErrorKind;
use x509_cert::der; // re-export of der crate
use x509_cert::spki; // re-export of spki crate

/// Structures/interfaces for SEV-SNP certificates.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate(x509_cert::Certificate);

const RSA_SSA_PSS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// Verify if the public key of one Certificate signs another Certificate.
impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<Self::Output> {
        let signer = &self.0 .0;
        let signee = &self.1 .0;

        if signee.signature_algorithm.oid != RSA_SSA_PSS_OID {
            return Err(io_error_other(format!(
                "unsupported signature algorithm: {:?}",
                signee.signature_algorithm
            )));
        }

        let rsa_verifying_key = {
            let signer_spki_ref = signer
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref();
            let signer_pubkey_rsa = rsa::RsaPublicKey::try_from(signer_spki_ref)
                .map_err(|e| io_error_other(format!("invalid RSA public key: {e:?}")))?;
            rsa::pss::VerifyingKey::<sha2::Sha384>::new(signer_pubkey_rsa)
        };

        let message = signee.tbs_certificate.to_der().map_err(|e| {
            io_error_other(format!("failed to encode tbs_certificate as DER: {e:?}"))
        })?;

        let rsa_signature = rsa::pss::Signature::try_from(signee.signature.raw_bytes())
            .map_err(|e| io_error_other(format!("invalid RSA signature: {e:?}")))?;

        rsa_verifying_key
            .verify(&message, &rsa_signature)
            .map_err(|e| {
                io_error_other(format!(
                    "Signer certificate does not RSA sign signee certificate: {e}"
                ))
            })
    }
}

impl Certificate {
    /// Gets a reference to the X509 certificate inside
    pub fn cert(&self) -> &x509_cert::Certificate {
        &self.0
    }

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

impl From<x509_cert::Certificate> for Certificate {
    fn from(value: x509_cert::Certificate) -> Self {
        Self(value)
    }
}

impl From<Certificate> for x509_cert::Certificate {
    fn from(Certificate(cert): Certificate) -> Self {
        cert
    }
}
