// SPDX-License-Identifier: Apache-2.0

fn main() {
    use std::path::Path;

    // Add in configurations to be checked within the code.
    println!("cargo::rustc-check-cfg=cfg(host)");
    println!("cargo::rustc-check-cfg=cfg(guest)");

    if Path::new("/dev/sev").exists() {
        println!("cargo:rustc-cfg=host");
    }

    if Path::new("/dev/sev-guest").exists() {
        println!("cargo:rustc-cfg=guest");
    }
}
