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
    use ::sev::certs::builtin::milan::ASK;

    let ask = ca::Certificate::decode(ASK, ()).unwrap();
    let cek = sev::Certificate::decode(CEK, ()).unwrap();

    (&ask, &cek).verify().unwrap();
}
