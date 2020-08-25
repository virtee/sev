// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

pub fn cached_chain_path() -> Option<PathBuf> {
    let mut path = dirs::home_dir()?;
    path.push(".cache");
    path.push("sev.chain");
    Some(path)
}

#[allow(dead_code)]
pub fn rm_cached_chain() {
    let path = cached_chain_path().unwrap();
    if std::path::Path::new(&path).exists() {
        std::fs::remove_file(path).unwrap();
    }
}
