// SPDX-License-Identifier: Apache-2.0

//! The `sev` crate provides an implementation of the [AMD Secure Encrypted
//! Virtualization (SEV)][SEV] APIs and the [SEV Secure Nested Paging
//! Firmware (SNP)][SNP] ABIs.
//!
//! [SEV]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/55766_SEV-KM_API_Specification.pdf
//! [SNP]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
//!
//! ## SEV APIs
//!
//! The linux kernel exposes two technically distinct AMD SEV APIs:
//!
//! 1. An API for managing the SEV platform itself
//! 2. An API for managing SEV-enabled KVM virtual machines
//!
//! This crate implements both of those APIs and offers them to client.
//! code through a flexible and type-safe high-level interface.
//!
//! ## SNP ABIs
//!
//! Like SEV, the linux kernel exposes another two different AMD SEV-SNP ABIs:
//!
//! 1. An ABI for managing the SEV-SNP platform itself
//! 2. An ABI for managing SEV-SNP enabled KVM virtual machines
//!
//! These new ABIs work only for **SEV-SNP** enabled hosts and guests.
//!
//! This crate implements APIs for both SEV and SEV-SNP management.
//!
//! ## SEV and SEV-SNP enablement
//!
//! By default, both the SEV and SEV-SNP libraries are compiled.
//! Because many modules provide support to both legacy SEV and SEV-SNP, they have been split into individual sub-modules `sev.rs` and `snp.rs`, isolating generation specific behavior.
//! If desired, you may opt to exclude either of the sub-modules by disabling its feature in your project's `Cargo.toml`  
//!
//! For example, to include the SEV APIs only:  
//! `sev = { version = "1.2.1", default-features = false, features = ["sev"] }`  
//!  
//! To include the SEV-SNP APIs only:  
//! `sev = { version = "1.2.1", default-features = false, features = ["snp"] }`  
//!
//! ## Platform Management
//!
//! Refer to the [firmware](crate::firmware) module for more information.
//!
//! ## Guest Management
//!
//! Refer to the [launch](crate::launch) module for more information.
//!
//! ## Cryptographic Verification
//!
//! To enable the cryptographic verification of certificate chains and
//! attestation reports, either the `openssl` or `crypto_nossl` feature
//! has to be enabled manually. With `openssl`, OpenSSL is used for the
//! verification. With `crypto_nossl`, OpenSSL is _not_ used for the
//! verification and instead pure-Rust libraries (e.g., `p384`, `rsa`,
//! etc.) are used. `openssl` and `crypto_nossl` are mutually exclusive,
//! and enabling both at the same time leads to a compiler error.
//!
//! ## Remarks
//!
//! Note that the linux kernel provides access to these APIs through a set
//! of `ioctl`s that are meant to be called on device nodes (`/dev/kvm` and
//! `/dev/sev`, to be specific). As a result, these `ioctl`s form the substrate
//! of the `sev` crate. Binaries that result from consumers of this crate are
//! expected to run as a process with the necessary privileges to interact
//! with the device nodes.
//!
//! ## Using the C API
//!
//! Projects in C can take advantage of the C API for the SEV [launch] ioctls.
//! To install the C API, users can use `cargo-c` with the features they would
//! like to produce and install a `pkg-config` file, a static library, a dynamic
//! library, and a C header:
//!
//! `cargo cinstall --prefix=/usr --libdir=/usr/lib64`
//!
//! [firmware]: ./src/firmware/
//! [launch]: ./src/launch/

#![deny(clippy::all)]
#![deny(missing_docs)]
#![allow(unknown_lints)]
#![allow(clippy::identity_op)]
#![allow(clippy::unreadable_literal)]

#[cfg(all(feature = "openssl", feature = "crypto_nossl"))]
compile_error!(
    "feature \"openssl\" and feature \"crypto_nossl\" cannot be enabled at the same time"
);

/// SEV and SEV-SNP certificates interface.
pub mod certs;

pub mod firmware;
#[cfg(target_os = "linux")]
pub mod launch;
#[cfg(all(
    any(feature = "sev", feature = "snp"),
    feature = "openssl",
    target_os = "linux"
))]
pub mod measurement;
#[cfg(all(target_os = "linux", feature = "openssl", feature = "sev"))]
pub mod session;
mod util;
pub mod vmsa;

/// Error module.
pub mod error;

pub use util::cached_chain;
use util::{TypeLoad, TypeSave};

#[cfg(all(feature = "openssl", feature = "sev"))]
use certs::sev::sev;

#[cfg(all(feature = "sev", feature = "openssl"))]
use certs::sev::ca::{Certificate, Chain as CertSevCaChain};

#[cfg(all(not(feature = "sev"), feature = "snp", feature = "openssl"))]
use certs::snp::ca::Chain as CertSnpCaChain;

#[cfg(all(feature = "sev", feature = "openssl"))]
use certs::sev::builtin as SevBuiltin;

#[cfg(all(not(feature = "sev"), feature = "snp", feature = "openssl"))]
use certs::snp::builtin as SnpBuiltin;

#[cfg(all(feature = "sev", target_os = "linux"))]
use crate::{certs::sev::sev::Certificate as SevCertificate, error::Indeterminate, launch::sev::*};

#[cfg(any(feature = "sev", feature = "snp"))]
use std::convert::TryFrom;

use std::io::{Read, Write};

#[cfg(all(feature = "sev", target_os = "linux"))]
use std::{
    collections::HashMap,
    io,
    mem::size_of,
    os::{
        fd::RawFd,
        raw::{c_int, c_uchar, c_uint, c_void},
    },
    slice::{from_raw_parts, from_raw_parts_mut},
    sync::Mutex,
};

#[cfg(all(feature = "sev", target_os = "linux"))]
use lazy_static::lazy_static;

use serde::{Deserialize, Serialize};

/// Information about the SEV platform version.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    /// The major version number.
    pub major: u8,

    /// The minor version number.
    pub minor: u8,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl From<u16> for Version {
    fn from(v: u16) -> Self {
        Self {
            major: ((v & 0xF0) >> 4) as u8,
            minor: (v & 0x0F) as u8,
        }
    }
}

/// A description of the SEV platform's build information.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Build {
    /// The version information.
    pub version: Version,

    /// The build number.
    pub build: u8,
}

impl std::fmt::Display for Build {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.version, self.build)
    }
}

impl codicon::Decoder<()> for Build {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, _: ()) -> std::io::Result<Self> {
        reader.load()
    }
}

impl codicon::Encoder<()> for Build {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.save(self)
    }
}

/// A representation for EPYC generational product lines.
///
/// Implements type conversion traits to determine which generation
/// a given SEV certificate chain corresponds to. This is helpful for
/// automatically detecting what platform code is running on, as one
/// can simply export the SEV certificate chain and attempt to produce
/// a `Generation` from it with the [TryFrom](
/// https://doc.rust-lang.org/std/convert/trait.TryFrom.html) trait.
///
/// ## Example
///
/// ```no_run
/// # #[cfg(features = "openssl")]
/// # {
///
/// // NOTE: The conversion traits require the `sev` crate to have the
/// // `openssl` feature enabled.
///
/// use std::convert::TryFrom;
/// use sev::certs::sev::Usage;
/// use sev::firmware::host::types::Firmware;
/// use sev::Generation;
///
/// let mut firmware = Firmware::open().expect("failed to open /dev/sev");
///
/// let chain = firmware.pdh_cert_export()
///     .expect("unable to export SEV certificates");
///
/// let id = firmware.get_identifier().expect("error fetching identifier");
///
/// // NOTE: Requesting a signed CEK from AMD's KDS has been omitted for
/// // brevity.
///
/// let generation = Generation::try_from(&chain).expect("not a SEV/ES chain");
/// match generation {
///     Generation::Naples => println!("Naples"),
///     Generation::Rome => println!("Rome"),
/// }
/// # }
/// ```
#[derive(Copy, Clone)]
pub enum Generation {
    /// First generation EPYC (SEV).
    #[cfg(feature = "sev")]
    Naples,

    /// Second generation EPYC (SEV, SEV-ES).
    #[cfg(feature = "sev")]
    Rome,

    /// Third generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Milan,

    /// Fourth generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Genoa,
}

#[cfg(all(feature = "sev", feature = "openssl"))]
impl From<Generation> for CertSevCaChain {
    fn from(generation: Generation) -> CertSevCaChain {
        use codicon::Decoder;

        let (ark, ask) = match generation {
            #[cfg(feature = "sev")]
            Generation::Naples => (SevBuiltin::naples::ARK, SevBuiltin::naples::ASK),
            #[cfg(feature = "sev")]
            Generation::Rome => (SevBuiltin::rome::ARK, SevBuiltin::rome::ASK),
            #[cfg(any(feature = "sev", feature = "snp"))]
            Generation::Milan => (SevBuiltin::milan::ARK, SevBuiltin::milan::ASK),
            #[cfg(any(feature = "sev", feature = "snp"))]
            Generation::Genoa => (SevBuiltin::genoa::ARK, SevBuiltin::genoa::ASK),
        };

        CertSevCaChain {
            ask: Certificate::decode(&mut &*ask, ()).unwrap(),
            ark: Certificate::decode(&mut &*ark, ()).unwrap(),
        }
    }
}

#[cfg(all(not(feature = "sev"), feature = "snp", feature = "openssl"))]
impl From<Generation> for CertSnpCaChain {
    fn from(gen: Generation) -> CertSnpCaChain {
        let (ark, ask) = match gen {
            Generation::Milan => (
                SnpBuiltin::milan::ark().unwrap(),
                SnpBuiltin::milan::ask().unwrap(),
            ),
            Generation::Genoa => (
                SnpBuiltin::genoa::ark().unwrap(),
                SnpBuiltin::genoa::ask().unwrap(),
            ),
        };

        CertSnpCaChain { ark, ask }
    }
}

#[cfg(all(feature = "sev", feature = "openssl"))]
impl TryFrom<&sev::Chain> for Generation {
    type Error = ();

    fn try_from(schain: &sev::Chain) -> Result<Self, Self::Error> {
        use crate::certs::sev::Verifiable;

        let naples: CertSevCaChain = Generation::Naples.into();
        let rome: CertSevCaChain = Generation::Rome.into();
        let milan: CertSevCaChain = Generation::Milan.into();
        let genoa: CertSevCaChain = Generation::Genoa.into();

        Ok(if (&naples.ask, &schain.cek).verify().is_ok() {
            Generation::Naples
        } else if (&rome.ask, &schain.cek).verify().is_ok() {
            Generation::Rome
        } else if (&milan.ask, &schain.cek).verify().is_ok() {
            Generation::Milan
        } else if (&genoa.ask, &schain.cek).verify().is_ok() {
            Generation::Genoa
        } else {
            return Err(());
        })
    }
}

#[cfg(any(feature = "sev", feature = "snp"))]
impl TryFrom<String> for Generation {
    type Error = ();

    fn try_from(val: String) -> Result<Self, Self::Error> {
        match &val.to_lowercase()[..] {
            #[cfg(feature = "sev")]
            "naples" => Ok(Self::Naples),

            #[cfg(feature = "sev")]
            "rome" => Ok(Self::Rome),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "milan" => Ok(Self::Milan),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "genoa" => Ok(Self::Genoa),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "bergamo" => Ok(Self::Genoa),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "siena" => Ok(Self::Genoa),

            _ => Err(()),
        }
    }
}

#[cfg(any(feature = "sev", feature = "snp"))]
impl Generation {
    /// Create a title-cased string identifying the SEV generation.
    pub fn titlecase(&self) -> String {
        match self {
            #[cfg(feature = "sev")]
            Self::Naples => "Naples".to_string(),

            #[cfg(feature = "sev")]
            Self::Rome => "Rome".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Milan => "Milan".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Genoa => "Genoa".to_string(),
        }
    }
}

// The C FFI interface to the library.

#[cfg(all(feature = "sev", target_os = "linux"))]
lazy_static! {
    static ref INIT_MAP: Mutex<HashMap<RawFd, Launcher<New, RawFd, RawFd>>> =
        Mutex::new(HashMap::new());
    static ref STARTED_MAP: Mutex<HashMap<RawFd, Launcher<Started, RawFd, RawFd>>> =
        Mutex::new(HashMap::new());
    static ref MEASURED_MAP: Mutex<HashMap<RawFd, Launcher<Measured, RawFd, RawFd>>> =
        Mutex::new(HashMap::new());
    static ref FINISHED_MAP: Mutex<HashMap<RawFd, Launcher<Finished, RawFd, RawFd>>> =
        Mutex::new(HashMap::new());
}

#[cfg(all(feature = "sev", target_os = "linux"))]
fn set_fw_err(ptr: *mut c_int, err: io::Error) {
    unsafe { *ptr = Indeterminate::from(err).into() };
}

/// A C FFI interface to the SEV_INIT ioctl.
///
/// # Safety
///
/// The caller of this function is responsible for ensuring that the pointer arguments are
/// valid.
#[cfg(all(feature = "sev", target_os = "linux"))]
#[no_mangle]
pub unsafe extern "C" fn sev_init(vm_fd: c_int, sev_fd: c_int, fw_err: *mut c_int) -> c_int {
    let vm: RawFd = vm_fd;
    let sev: RawFd = sev_fd;

    match Launcher::new(vm, sev) {
        Ok(launcher) => {
            let mut map = INIT_MAP.lock().unwrap();
            map.insert(vm_fd, launcher);

            0
        }
        Err(e) => {
            set_fw_err(fw_err, e);
            -1
        }
    }
}

/// A C FFI interface to the SEV_ES_INIT ioctl.
///
/// # Safety
///
/// The caller of this function is responsible for ensuring that the pointer arguments are
/// valid.
#[cfg(all(feature = "sev", target_os = "linux"))]
#[no_mangle]
pub unsafe extern "C" fn sev_es_init(vm_fd: c_int, sev_fd: c_int, fw_err: *mut c_int) -> c_int {
    let vm: RawFd = vm_fd;
    let sev: RawFd = sev_fd;

    match Launcher::new_es(vm, sev) {
        Ok(launcher) => {
            let mut map = INIT_MAP.lock().unwrap();
            map.insert(vm_fd, launcher);

            0
        }
        Err(e) => {
            set_fw_err(fw_err, e);
            -1
        }
    }
}

/// A C FFI interface to the SEV_LAUNCH_START ioctl.
///
/// # Safety
///
/// The caller of this function is responsible for ensuring that the pointer arguments are
/// valid.
#[cfg(all(feature = "sev", target_os = "linux"))]
#[no_mangle]
pub unsafe extern "C" fn sev_launch_start(
    vm_fd: c_int,
    policy: u32,
    cert_bytes: *const c_void,
    session_bytes: *const c_void,
    fw_err: *mut c_int,
) -> c_int {
    let mut map = INIT_MAP.lock().unwrap();
    let launcher = match map.remove(&vm_fd) {
        Some(l) => l,
        None => return -1,
    };

    let policy = Policy::from(policy);
    let cert: SevCertificate = unsafe { *(cert_bytes as *const SevCertificate) };
    let session: Session = unsafe { *(session_bytes as *const Session) };

    let start = Start {
        policy,
        cert,
        session,
    };

    match launcher.start(start) {
        Ok(started) => {
            let mut map = STARTED_MAP.lock().unwrap();
            if map.insert(vm_fd, started).is_none() {
                return 0;
            }
            -1
        }
        Err(e) => {
            set_fw_err(fw_err, e);
            -1
        }
    }
}

/// A C FFI interface to the SEV_LAUNCH_UPDATE ioctl.
///
/// # Safety
///
/// The caller of this function is responsible for ensuring that the pointer arguments are
/// valid.
#[cfg(all(feature = "sev", target_os = "linux"))]
#[no_mangle]
pub unsafe extern "C" fn sev_launch_update_data(
    vm_fd: c_int,
    uaddr: u64,
    len: u64,
    fw_err: *mut c_int,
) -> c_int {
    let mut map = STARTED_MAP.lock().unwrap();
    let launcher = match map.get_mut(&vm_fd) {
        Some(l) => l,
        None => return -1,
    };

    let slice: &[u8] = unsafe { from_raw_parts(uaddr as *const u8, len as usize) };
    if let Err(e) = launcher.update_data(slice) {
        set_fw_err(fw_err, e);
        return -1;
    }

    0
}

/// A C FFI interface to the SEV_LAUNCH_UPDATE_VMSA ioctl.
///
/// # Safety
///
/// The caller of this function is responsible for ensuring that the pointer arguments are
/// valid.
#[cfg(all(feature = "sev", target_os = "linux"))]
#[no_mangle]
pub unsafe extern "C" fn sev_launch_update_vmsa(vm_fd: c_int, fw_err: *mut c_int) -> c_int {
    let mut map = STARTED_MAP.lock().unwrap();
    let launcher = match map.get_mut(&vm_fd) {
        Some(l) => l,
        None => return -1,
    };

    if let Err(e) = launcher.update_vmsa() {
        set_fw_err(fw_err, e);
        return -1;
    }

    0
}

/// A C FFI interface to the SEV_LAUNCH_MEASURE ioctl.
///
/// # Safety
///
/// The caller of this function is responsible for ensuring that the pointer arguments are
/// valid.
///
/// The "measurement_data" argument should be a valid pointer able to hold the meausurement's
/// bytes. The measurement is 48 bytes in size.
#[cfg(all(feature = "sev", target_os = "linux"))]
#[no_mangle]
pub unsafe extern "C" fn sev_launch_measure(
    vm_fd: c_int,
    measurement_data: *mut c_uchar,
    fw_err: &mut c_int,
) -> c_int {
    let mut map = STARTED_MAP.lock().unwrap();
    let launcher = match map.remove(&vm_fd) {
        Some(l) => l,
        None => return -1,
    };

    match launcher.measure() {
        Ok(m) => {
            let mut map = MEASURED_MAP.lock().unwrap();
            let measure = m.measurement();
            let slice: &mut [u8] = unsafe {
                from_raw_parts_mut(
                    (&measure as *const Measurement) as *mut u8,
                    size_of::<Measurement>(),
                )
            };
            map.insert(vm_fd, m);

            libc::memcpy(
                measurement_data as _,
                slice.as_ptr() as _,
                size_of::<Measurement>(),
            );

            0
        }
        Err(e) => {
            set_fw_err(fw_err, e);

            -1
        }
    }
}

/// A C FFI interface to the SEV_LAUNCH_SECRET ioctl.
///
/// # Safety
///
/// The caller of this function is responsible for ensuring that the pointer arguments are
/// valid.
#[cfg(all(feature = "sev", target_os = "linux"))]
#[no_mangle]
pub unsafe extern "C" fn sev_inject_launch_secret(
    vm_fd: c_int,
    header_bytes: *const c_uchar,
    ct_bytes: *const c_uchar,
    ct_size: u32,
    paddr: *const c_void,
    fw_err: *mut c_int,
) -> c_int {
    let mut map = MEASURED_MAP.lock().unwrap();
    let launcher = match map.get_mut(&vm_fd) {
        Some(l) => l,
        None => return -1,
    };

    let header = header_bytes as *const Header;
    let ciphertext = {
        let bytes: &[u8] = unsafe { from_raw_parts(ct_bytes, ct_size as usize) };

        bytes.to_owned().to_vec()
    };

    let secret = Secret {
        header: unsafe { *header },
        ciphertext,
    };

    match launcher.inject(&secret, paddr as usize) {
        Ok(()) => 0,
        Err(e) => {
            set_fw_err(fw_err, e);
            -1
        }
    }
}

/// A C FFI interface to the SEV_LAUNCH_FINISH ioctl.
///
/// # Safety
///
/// The caller of this function is responsible for ensuring that the mnonce is 16 bytes in
/// size.
///
/// The caller of this function is responsible for ensuring that the pointer arguments are
/// valid.
#[cfg(all(feature = "sev", target_os = "linux"))]
#[no_mangle]
pub unsafe extern "C" fn sev_launch_finish(vm_fd: c_int, fw_err: *mut c_int) -> c_int {
    let mut map = MEASURED_MAP.lock().unwrap();
    let launcher = match map.remove(&vm_fd) {
        Some(l) => l,
        None => return -1,
    };

    match launcher.finish_attestable() {
        Ok(l) => {
            let mut map = FINISHED_MAP.lock().unwrap();
            map.insert(vm_fd, l);

            0
        }
        Err(e) => {
            set_fw_err(fw_err, e);
            -1
        }
    }
}

/// A C FFI interface to the SEV_ATTESTATION_REPORT ioctl.
///
/// # Safety
///
/// The caller of this function is responsible for ensuring that the pointer arguments are
/// valid.
#[cfg(all(feature = "sev", target_os = "linux"))]
#[allow(unused_assignments)]
#[no_mangle]
pub unsafe extern "C" fn sev_attestation_report(
    vm_fd: c_int,
    mnonce: *const c_uchar,
    mnonce_len: u32,
    mut bytes: *mut c_uchar,
    len: *mut c_uint,
    fw_err: *mut c_int,
) -> c_int {
    let mut map = FINISHED_MAP.lock().unwrap();
    let launcher = match map.get_mut(&vm_fd) {
        Some(l) => l,
        None => return -1,
    };

    if mnonce_len != 16 {
        return -1;
    }

    let m: &[u8] = from_raw_parts(mnonce, 16);

    let mut mnonce_cpy = [0u8; 16];
    mnonce_cpy.copy_from_slice(m);

    match launcher.report(mnonce_cpy) {
        Ok(r) => {
            *len = r.len() as _;
            bytes = libc::malloc(r.len()) as *mut c_uchar;

            libc::memcpy(bytes as _, r.as_ptr() as _, r.len());

            0
        }
        Err(e) => {
            set_fw_err(fw_err, e);
            -1
        }
    };

    -1
}
