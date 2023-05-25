// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "snp")]
use sev::firmware::guest::*;

#[cfg(feature = "snp")]
#[cfg_attr(not(has_sev_guest), ignore)]
#[test]
fn get_report() {
    let unique_data = [0u8; 64];

    let mut fw = Firmware::open().unwrap();

    fw.get_report(None, Some(unique_data), None).unwrap();
}

#[cfg(feature = "snp")]
#[cfg_attr(not(has_sev_guest), ignore)]
#[test]
fn get_ext_report() {
    let unique_data = [0u8; 64];

    let mut fw = Firmware::open().unwrap();

    fw.get_ext_report(None, Some(unique_data), None).unwrap();
}

#[cfg(feature = "snp")]
#[cfg_attr(not(has_sev_guest), ignore)]
#[test]
fn get_derived_key() {
    let derived_key = DerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0);

    let mut fw = Firmware::open().unwrap();

    fw.get_derived_key(None, derived_key).unwrap();
}
