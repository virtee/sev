// SPDX-License-Identifier: Apache-2.0

//! X.509 certificate signature verification (pure-Rust backend).
//!
//! Implements [`Verifiable`](crate::attestation::verifier::Verifiable) for
//! `(signer, signee)` certificate pairs using `x509-cert`, `rsa`, and `sha2`.
//! This is the building block for chain verification in [`super::chain`].
//!
//! Currently supports RSA-PSS with SHA-384, matching AMD SNP certificate chains.

use crate::attestation::endorser::snp::Certificate;
use crate::attestation::verifier::Verifiable;

use rsa::signature;
use signature::Verifier;
use std::convert::TryFrom;
use std::io::{self, ErrorKind, Result};
use x509_cert::der::{referenced::OwnedToRef, Encode};
use x509_cert::spki::ObjectIdentifier;

const RSA_SSA_PSS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// Verify that one certificate's public key signed another certificate.
///
/// `self.0` is the **signer** (issuer) and `self.1` is the **signee** (subject).
/// The signee's TBS certificate is hashed and checked against the signer's RSA
/// public key using RSASSA-PSS with SHA-384.
///
/// Returns an error if the signee uses an unsupported signature algorithm.
impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<Self::Output> {
        let signer: x509_cert::Certificate = self.0.into();
        let signee: x509_cert::Certificate = self.1.into();

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

fn io_error_other<S: Into<String>>(error: S) -> io::Error {
    io::Error::new(ErrorKind::Other, error.into())
}
