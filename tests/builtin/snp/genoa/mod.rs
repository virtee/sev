// SPDX-License-Identifier: Apache-2.0

use ::sev::attestation::endorser::snp::Certificate;
use std::io::Result;

/// The public Genoa ARK certificate (PEM-encoded).
pub const ARK: &[u8] = include_bytes!("ark.pem");

/// The public Genoa ASK certificate (PEM-encoded).
pub const ASK: &[u8] = include_bytes!("ask.pem");

/// Get the Genoa ARK Certificate.
pub fn ark() -> Result<Certificate> {
    Certificate::from_pem(ARK)
}

/// Get the Genoa ASK Certificate.
pub fn ask() -> Result<Certificate> {
    Certificate::from_pem(ASK)
}

mod tests {
    use super::*;
    use ::sev::attestation::verifier::Verifiable;

    #[test]
    fn ark_self_signed() {
        let ark = ark().unwrap();

        (&ark, &ark).verify().unwrap();
    }

    #[test]
    fn ark_signs_ask() {
        let ark = ark().unwrap();
        let ask = ask().unwrap();

        (&ark, &ask).verify().unwrap();
    }
}
