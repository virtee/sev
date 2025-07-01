// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "snp", target_os = "linux"))]

use sev::firmware::guest::*;

#[cfg_attr(not(guest), ignore)]
#[test]
fn get_report() {
    let unique_data = [0u8; 64];

    let mut fw = Firmware::open().unwrap();

    fw.get_report(None, Some(unique_data), None).unwrap();
}

#[cfg_attr(not(guest), ignore)]
#[test]
fn get_ext_report() {
    let unique_data = [0u8; 64];

    let mut fw = Firmware::open().unwrap();

    fw.get_ext_report(None, Some(unique_data), None).unwrap();
}

#[cfg_attr(not(guest), ignore)]
#[test]
fn get_derived_key() {
    let derived_key = DerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0, None);

    let mut fw = Firmware::open().unwrap();

    fw.get_derived_key(None, derived_key).unwrap();
}

#[cfg_attr(not(guest), ignore)]
#[test]
fn guest_fw_error() {
    let derived_key = DerivedKey::new(
        false,
        GuestFieldSelect(48),
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        Some(0xFFFFFFFFFFFFFFFF),
    );

    let mut fw = Firmware::open().unwrap();

    let fw_err = fw
        .get_derived_key(None, derived_key)
        .unwrap_err()
        .to_string();

    assert_eq!(fw_err, "Firmware Error Encountered: Known SEV FW Error: Status Code: 0x16: Given parameter is invalid.")
}
