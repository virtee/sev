// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn decode() {
    sev::Certificate::decode(&mut &CEK[..], ()).unwrap();
}

#[test]
fn encode() {
    let cek = sev::Certificate::decode(&mut &CEK[..], ()).unwrap();

    let mut output = Vec::new();
    cek.encode(&mut output, ()).unwrap();
    assert_eq!(CEK.len(), output.len());
    assert_eq!(CEK.to_vec(), output);
}

#[cfg(feature = "openssl")]
#[test]
fn verify() {
    use ::sev::certs::sev::builtin::naples::ASK;

    let mut mut_cek = CEK;
    let mut mut_ask = ASK;

    let ask = ca::Certificate::decode(&mut mut_ask, ()).unwrap();
    let cek = sev::Certificate::decode(&mut mut_cek, ()).unwrap();

    (&ask, &cek).verify().unwrap();
    // assert!((&cek, &ask).verify().is_err());
}
