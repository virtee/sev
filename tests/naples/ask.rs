// SPDX-License-Identifier: Apache-2.0

use super::*;
use ::sev::certs::sev::builtin::naples::*;

#[test]
fn decode() {
    ca::Certificate::decode(&mut &ASK[..], ()).unwrap();
}

#[test]
fn encode() {
    let ask = ca::Certificate::decode(&mut &ASK[..], ()).unwrap();

    let mut output = Vec::new();
    ask.encode(&mut output, ()).unwrap();
    assert_eq!(ASK.len(), output.len());
    assert_eq!(ASK.to_vec(), output);
}

#[cfg(feature = "openssl")]
#[test]
fn verify() {
    let mut mut_ark = ARK;
    let mut mut_ask = ASK;
    let ark = ca::Certificate::decode(&mut mut_ark, ()).unwrap();
    let ask = ca::Certificate::decode(&mut mut_ask, ()).unwrap();

    (&ark, &ask).verify().unwrap();
    assert!((&ask, &ark).verify().is_err());
}
