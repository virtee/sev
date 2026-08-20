// SPDX-License-Identifier: Apache-2.0

//! X.509 certificate signature verification (OpenSSL backend).
//!
//! Implements [`Verifiable`](crate::attestation::verifier::Verifiable) for
//! `(signer, signee)` certificate pairs using OpenSSL. This is the building
//! block for chain verification in [`super::chain`].

use crate::attestation::endorser::snp::Certificate;
use crate::attestation::verifier::Verifiable;

use openssl::pkey::{PKey, Public};
use openssl::x509::X509;

use std::io::{Error, ErrorKind, Result};

/// Verify that one certificate's public key signed another certificate.
///
/// `self.0` is the **signer** (issuer) and `self.1` is the **signee** (subject).
/// OpenSSL validates the X.509 signature on `signee` using the public key
/// extracted from `signer`.
///
/// Used for ARK self-signature, ARK → ASK, ASK → VCEK/VLEK, and similar
/// checks during chain validation.
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
