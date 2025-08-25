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
    let mut mut_pdh = PDH;
    let mut mut_pek = PEK;
    let pek = sev::Certificate::decode(&mut mut_pek, ()).unwrap();
    let pdh = sev::Certificate::decode(&mut mut_pdh, ()).unwrap();

    (&pek, &pdh).verify().unwrap();
    assert!((&pdh, &pek).verify().is_err());
}
