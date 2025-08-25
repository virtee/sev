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

#![cfg(all(feature = "sev", feature = "dangerous_hw_tests"))]

#[cfg(feature = "openssl")]
use crate::{
    certs::sev::{ca::Chain as CaChain, Chain as FullChain},
    firmware::host::Firmware,
    sev::Certificate,
    Generation,
};

#[cfg(feature = "openssl")]
use reqwest::{
    blocking::{get, Response},
    StatusCode,
};

use std::{
    env,
    path::{Path, PathBuf},
};

#[cfg(feature = "openssl")]
use std::io::Cursor;

#[cfg(feature = "openssl")]
use crate::parser::Decoder;

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

/// Remove any certificates that may have been chached to reset
/// testing for SEV APIS.
pub fn rm_cached_chain() {
    let paths = path();
    if let Some(path) = paths.first() {
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
}

/// Request CEK certificate from AMD KDS and generate a full chain.
#[cfg(all(feature = "sev", feature = "openssl"))]
pub fn get_chain() -> FullChain {
    use std::convert::TryFrom;

    let mut firmware = Firmware::open().unwrap();

    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

    let mut sev_chain = firmware.pdh_cert_export().unwrap();

    let id = firmware.get_identifier().unwrap();

    let url = format!("{}/{}", CEK_SVC, id);

    // VCEK in DER format
    let vcek_rsp: Response = get(url).expect("Failed to get CEK certificate");

    let cek_resp_bytes = match vcek_rsp.status() {
        StatusCode::OK => {
            let vcek_rsp_bytes: Vec<u8> = vcek_rsp.bytes().unwrap().to_vec();
            vcek_rsp_bytes
        }
        _ => panic!("Cek request returned an error"),
    };

    // Create a Cursor around the byte vector
    let mut cursor = Cursor::new(cek_resp_bytes);

    sev_chain.cek = Certificate::decode(&mut cursor, ()).expect("Failed to decode CEK cert");

    let ca_chain: CaChain = Generation::try_from(&sev_chain)
        .expect("Failed to generate SEV CA chain")
        .into();

    FullChain {
        ca: ca_chain,
        sev: sev_chain,
    }
}
