// SPDX-License-Identifier: Apache-2.0

mod milan;
mod naples;
mod rome;

#[test]
#[cfg(feature = "openssl")]
fn test_for_verify_false_positive() {
    use ::sev::certs::sev::*;
    use codicon::Decoder;

    // https://github.com/enarx/enarx/issues/520
    let naples_cek = sev::Certificate::decode(&mut &naples::CEK[..], ()).unwrap();
    let rome_ask = ca::Certificate::decode(&mut &builtin::rome::ASK[..], ()).unwrap();
    let milan_ask = ca::Certificate::decode(&mut &builtin::milan::ASK[..], ()).unwrap();
    assert!((&rome_ask, &naples_cek).verify().is_err());
    assert!((&milan_ask, &naples_cek).verify().is_err());
}
