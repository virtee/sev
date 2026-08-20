// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::sev::cert::{Certificate, EcdsaSignature, Usage};
use crate::attestation::endorser::sev::PublicKey;
use crate::attestation::evidence::sev::LegacyAttestationReport;
use crate::attestation::verifier::Verifiable;

use openssl::{ec::EcKey, ecdsa::EcdsaSig, pkey::Public, sha::Sha256};
use std::convert::{TryFrom, TryInto};
use std::io::{Error, ErrorKind, Result};

impl Verifiable for (&Certificate, &LegacyAttestationReport) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let sev_pub_key: PublicKey<Usage> =
            <PublicKey<Usage> as TryFrom<&Certificate>>::try_from(self.0)?;
        let pub_key: &EcKey<Public> = &sev_pub_key.ec_key()?;

        let sig = EcdsaSignature::try_from(self.1.signature.as_slice())?;

        let sig: EcdsaSig = sig.try_into()?;

        let mut hasher = Sha256::new();
        hasher.update(&self.1.measurable_bytes());
        let base_digest = hasher.finish();

        let signed = sig.verify(&base_digest, pub_key)?;
        match signed {
            true => Ok(()),
            false => Err(Error::new(
                ErrorKind::Other,
                "PEK does not sign the attestation report",
            )),
        }
    }
}
