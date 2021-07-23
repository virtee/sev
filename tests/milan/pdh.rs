// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn decode() {
    sev::Certificate::decode(&mut &PDH[..], ()).unwrap();
}

#[test]
fn encode() {
    let pdh = sev::Certificate::decode(&mut &PDH[..], ()).unwrap();

    let mut output = Vec::new();
    pdh.encode(&mut output, ()).unwrap();
    assert_eq!(PDH.len(), output.len());
    assert_eq!(PDH.to_vec(), output);
}

#[cfg(feature = "openssl")]
#[test]
fn verify() {
    let pek = sev::Certificate::decode(PEK, ()).unwrap();
    let pdh = sev::Certificate::decode(PDH, ()).unwrap();

    (&pek, &pdh).verify().unwrap();
    assert!((&pdh, &pek).verify().is_err());
}
