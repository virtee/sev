// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn decode() {
    cert::Certificate::decode(&mut &PEK[..], ()).unwrap();
}

#[test]
fn encode() {
    let pek = cert::Certificate::decode(&mut &PEK[..], ()).unwrap();

    let mut output = Vec::new();
    pek.encode(&mut output, ()).unwrap();
    assert_eq!(PEK.len(), output.len());
    assert_eq!(PEK.to_vec(), output);
}

#[cfg(feature = "crypto-openssl")]
#[test]
fn verify() {
    let mut mut_cek = CEK;
    let mut mut_oca = OCA;
    let mut mut_pek = PEK;
    let cek = cert::Certificate::decode(&mut mut_cek, ()).unwrap();
    let oca = cert::Certificate::decode(&mut mut_oca, ()).unwrap();
    let pek = cert::Certificate::decode(&mut mut_pek, ()).unwrap();

    (&cek, &pek).verify().unwrap();
    assert!((&pek, &cek).verify().is_err());

    (&oca, &pek).verify().unwrap();
    assert!((&pek, &oca).verify().is_err());
}
