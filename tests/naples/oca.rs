// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn decode() {
    cert::Certificate::decode(&mut &OCA[..], ()).unwrap();
}

#[test]
fn encode() {
    let oca = cert::Certificate::decode(&mut &OCA[..], ()).unwrap();

    let mut output = Vec::new();
    oca.encode(&mut output, ()).unwrap();
    assert_eq!(OCA.len(), output.len());
    assert_eq!(OCA.to_vec(), output);
}

#[cfg(feature = "crypto-openssl")]
#[test]
fn verify() {
    let mut mut_oca = OCA;
    let oca = cert::Certificate::decode(&mut mut_oca, ()).unwrap();
    (&oca, &oca).verify().unwrap();
}

#[cfg(feature = "crypto-openssl")]
#[test]
fn create() {
    let mut pdh = cert::Certificate::decode(&mut &PDH[..], ()).unwrap();
    let (mut oca, key) = cert::Certificate::generate(cert::Usage::OCA).unwrap();

    assert!((&pdh, &pdh).verify().is_err());
    assert!((&oca, &pdh).verify().is_err());
    assert!((&oca, &oca).verify().is_err());

    key.sign(&mut oca).unwrap();

    assert!((&pdh, &pdh).verify().is_err());
    assert!((&oca, &pdh).verify().is_err());
    (&oca, &oca).verify().unwrap();

    key.sign(&mut pdh).unwrap();
    (&oca, &pdh).verify().unwrap();
}
