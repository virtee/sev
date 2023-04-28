// SPDX-License-Identifier: Apache-2.0

//! Utilities for adhering to a cached SEV chain convention.
//!
//! The search path for the SEV chain is:
//!   1. The path specified in the "SEV_CHAIN" environment variable
//!      (if present).
//!   2. `$HOME/.cache/amd-sev/chain`
//!   3. `/var/cache/amd-sev/chain`
//!
//! An entire certificate chain can be created using the `sevctl`
//! utility.

#[cfg(feature = "sev")]
use crate::certs::sev::Chain;

use std::{
    env,
    path::{Path, PathBuf},
};

#[cfg(feature = "sev")]
use std::{
    fs::File,
    io::{ErrorKind, Result},
};

#[cfg(feature = "sev")]
use codicon::Decoder;

fn append_rest<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut path = path.as_ref().to_path_buf();
    path.push("amd-sev");
    path.push("chain");
    path
}

/// Returns the path stored in the optional `SEV_CHAIN`
/// environment variable.
pub fn env_var() -> Option<PathBuf> {
    env::var("SEV_CHAIN").ok().map(PathBuf::from)
}

/// Returns the "user-level" search path for the SEV
/// certificate chain (`$HOME/.cache/amd-sev/chain`).
pub fn home() -> Option<PathBuf> {
    dirs::cache_dir().map(append_rest)
}

/// Returns the "system-level" search path for the SEV
/// certificate chain (`/var/cache/amd-sev/chain`).
pub fn sys() -> Option<PathBuf> {
    let sys = PathBuf::from("/var/cache");
    if sys.exists() {
        Some(append_rest(sys))
    } else {
        None
    }
}

/// Returns the list of search paths in the order that they
/// will be searched for the SEV certificate chain.
pub fn path() -> Vec<PathBuf> {
    vec![env_var(), home(), sys()]
        .into_iter()
        .flatten()
        .collect()
}

/// Searches for and decodes an SEV certificate chain.
#[cfg(feature = "sev")]
pub fn get() -> Result<Chain> {
    let not_found: std::io::Error = ErrorKind::NotFound.into();

    let paths: Vec<_> = path().into_iter().filter(|p| p.exists()).collect();
    let file_name = paths.first().ok_or(not_found)?;
    let mut file = File::open(file_name)?;
    Chain::decode(&mut file, ())
}
