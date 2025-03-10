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

#[cfg(all(feature = "sev", feature = "dangerous_hw_tests"))]
pub use util::cached_chain;

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

#[cfg(any(feature = "sev", feature = "snp"))]
use std::convert::TryFrom;

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

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

    /// Fifth generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Turin,
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
            #[cfg(any(feature = "sev", feature = "snp"))]
            Generation::Turin => (SevBuiltin::turin::ARK, SevBuiltin::turin::ASK),
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
            Generation::Turin => (
                SnpBuiltin::turin::ark().unwrap(),
                SnpBuiltin::turin::ask().unwrap(),
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
        let turin: CertSevCaChain = Generation::Turin.into();

        Ok(if (&naples.ask, &schain.cek).verify().is_ok() {
            Generation::Naples
        } else if (&rome.ask, &schain.cek).verify().is_ok() {
            Generation::Rome
        } else if (&milan.ask, &schain.cek).verify().is_ok() {
            Generation::Milan
        } else if (&genoa.ask, &schain.cek).verify().is_ok() {
            Generation::Genoa
        } else if (&turin.ask, &schain.cek).verify().is_ok() {
            Generation::Turin
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

            #[cfg(any(feature = "sev", feature = "snp"))]
            "turin" => Ok(Self::Turin),

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

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Turin => "Turin".to_string(),
        }
    }
}
