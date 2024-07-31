// SPDX-License-Identifier: Apache-2.0

fn main() {
    use std::path::Path;

    // Register custom cfg flags for `has_sev` and `has_sev_guest`.
    println!("cargo:rustc-check-cfg=cfg(has_sev)");
    println!("cargo:rustc-check-cfg=cfg(has_sev_guest)");

    // If the device driver is found, set the cfg flag
    if cfg!(feature = "hw_tests") || Path::new("/dev/sev").exists() {
        println!("cargo:rustc-cfg=has_sev");
    }

    if cfg!(feature = "hw_tests") || Path::new("/dev/sev-guest").exists() {
        println!("cargo:rustc-cfg=has_sev_guest");
    }
}
