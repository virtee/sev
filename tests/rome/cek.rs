// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn decode() {
    cert::Certificate::decode(&mut &CEK[..], ()).unwrap();
}

#[test]
fn encode() {
    let cek = cert::Certificate::decode(&mut &CEK[..], ()).unwrap();

    let mut output = Vec::new();
    cek.encode(&mut output, ()).unwrap();
    assert_eq!(CEK.len(), output.len());
    assert_eq!(CEK.to_vec(), output);
}

#[cfg(feature = "crypto-openssl")]
#[test]
fn verify() {
    use ::sev::attestation::endorser::sev::builtin::rome::ASK;

    let mut mut_cek = CEK;
    let mut mut_ask = ASK;

    let ask = ca::Certificate::decode(&mut mut_ask, ()).unwrap();
    let cek = cert::Certificate::decode(&mut mut_cek, ()).unwrap();

    (&ask, &cek).verify().unwrap();
}
