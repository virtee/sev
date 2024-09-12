// SPDX-License-Identifier: Apache-2.0

fn main() {
    use std::path::Path;

    // Add in configurations to be checked within the code.
    println!("cargo::rustc-check-cfg=cfg(has_sev)");
    println!("cargo::rustc-check-cfg=cfg(has_sev_guest)");

    if cfg!(feature = "hw_tests") || Path::new("/dev/sev").exists() {
        println!("cargo:rustc-cfg=has_sev");
    }

    if cfg!(feature = "hw_tests") || Path::new("/dev/sev-guest").exists() {
        println!("cargo:rustc-cfg=has_sev_guest");
    }
}
