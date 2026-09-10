// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::sev::{ca, cert, PublicKey, Signature};
use crate::attestation::verifier::Verifiable;

use std::convert::TryFrom;
use std::io::{ErrorKind, Result};

impl Verifiable for (&ca::Certificate, &ca::Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key: PublicKey<ca::Usage> =
            <PublicKey<ca::Usage> as TryFrom<&ca::Certificate>>::try_from(self.0)?;
        let sig: Signature = <Signature as TryFrom<&ca::Certificate>>::try_from(self.1)?;
        key.verify(self.1, &sig)
    }
}

impl Verifiable for (&cert::Certificate, &cert::Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key = <PublicKey<cert::Usage> as TryFrom<&cert::Certificate>>::try_from(self.0)?;

        let sigs: [Option<Signature>; 2] =
            <[Option<Signature>; 2] as TryFrom<&cert::Certificate>>::try_from(self.1)?;
        for sig in sigs.iter().flatten() {
            if key.verify(self.1, sig).is_ok() {
                return Ok(());
            }
        }

        Err(ErrorKind::InvalidInput.into())
    }
}

impl Verifiable for (&ca::Certificate, &cert::Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key: PublicKey<ca::Usage> =
            <PublicKey<ca::Usage> as TryFrom<&ca::Certificate>>::try_from(self.0)?;

        let sigs: [Option<Signature>; 2] =
            <[Option<Signature>; 2] as TryFrom<&cert::Certificate>>::try_from(self.1)?;
        for sig in sigs.iter().flatten() {
            if key.verify(self.1, sig).is_ok() {
                return Ok(());
            }
        }

        Err(ErrorKind::InvalidInput.into())
    }
}
