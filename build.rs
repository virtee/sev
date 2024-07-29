// SPDX-License-Identifier: Apache-2.0

fn main() {
    use std::path::Path;

    // Add all of the possible configurations.
    println!("cargo:rustc-check-cfg=cfg(has_sev)");
    println!("cargo:rustc-check-cfg=cfg(has_sev_guest)");

    // Check if the configuration should be set to enabled.
    if cfg!(feature = "hw_tests") || Path::new("/dev/sev").exists() {
        println!("cargo:rustc-cfg=has_sev");
    }

    if cfg!(feature = "hw_tests") || Path::new("/dev/sev-guest").exists() {
        println!("cargo:rustc-cfg=has_sev_guest");
    }
}
