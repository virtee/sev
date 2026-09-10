// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "crypto-openssl")]

#[cfg(all(
    target_os = "linux",
    feature = "sev",
    feature = "launch",
    feature = "verifier"
))]
mod initialized {
    use ::sev::{
        attestation::endorser::sev::builtin::naples::*, attestation::endorser::sev::*,
        attestation::verifier::Verifiable, launch, launch::sev::session::Session, parser::Decoder,
    };
    use std::convert::*;

    #[test]
    fn create() {
        Session::try_from(launch::sev::Policy::default()).unwrap();
    }

    #[test]
    fn start() {
        const CEK: &[u8] = include_bytes!("naples/cek.cert");
        const OCA: &[u8] = include_bytes!("naples/oca.cert");
        const PEK: &[u8] = include_bytes!("naples/pek.cert");
        const PDH: &[u8] = include_bytes!("naples/pdh.cert");

        let session = Session::try_from(launch::sev::Policy::default()).unwrap();
        session
            .start(Chain {
                ca: ca::Chain {
                    ark: ca::Certificate::decode(&mut &ARK[..], ()).unwrap(),
                    ask: ca::Certificate::decode(&mut &ASK[..], ()).unwrap(),
                },
                sev: cert::Chain {
                    cek: cert::Certificate::decode(&mut &CEK[..], ()).unwrap(),
                    oca: cert::Certificate::decode(&mut &OCA[..], ()).unwrap(),
                    pek: cert::Certificate::decode(&mut &PEK[..], ()).unwrap(),
                    pdh: cert::Certificate::decode(&mut &PDH[..], ()).unwrap(),
                },
            })
            .unwrap();
    }
}
