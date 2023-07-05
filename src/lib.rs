// SPDX-License-Identifier: Apache-2.0

//! The `sev` crate provides an implementation of [AMD Secure Encrypted
//! Virtualization (SEV)](https://developer.amd.com/sev/) APIs.
//!
//! The Linux kernel exposes two technically distinct AMD SEV APIs:
//!
//! 1. An API for managing the SEV platform itself
//! 2. An API for managing SEV-enabled KVM virtual machines
//!
//! This crate implements both of those APIs and offers them to client
//! code through a flexible and type-safe high level interface.
//!
//! ## Platform Management
//!
//! Refer to the [`firmware`] module for more information.
//!
//! ## Guest Management
//!
//! Refer to the [`launch`] module for more information.
//!
//! ## Remarks
//!
//! Note that the Linux kernel provides access to these APIs through a set
//! of `ioctl`s that are meant to be called on device nodes (`/dev/kvm` and
//! `/dev/sev`, to be specific). As a result, these `ioctl`s form the substrate
//! of the `sev` crate. Binaries that result from consumers of this crate are
//! expected to run as a process with the necessary privileges to interact
//! with the device nodes.
//!
//! [`firmware`]: ./src/firmware/
//! [`launch`]: ./src/launch/

#![deny(clippy::all)]
#![deny(missing_docs)]
#![allow(unknown_lints)]
#![allow(clippy::identity_op)]
#![allow(clippy::unreadable_literal)]

/// SEV and SEV-SNP certificates interface.
pub mod certs;

pub mod firmware;
pub mod launch;
#[cfg(all(feature = "openssl", feature = "sev"))]
pub mod session;
mod util;
pub mod vmsa;

/// Error module.
pub mod error;

pub use util::cached_chain;
use util::{TypeLoad, TypeSave};

#[cfg(all(feature = "openssl", feature = "sev"))]
use certs::sev::sev;

#[cfg(feature = "openssl")]
use certs::sev::ca::{Certificate, Chain as CertSevCaChain};

#[cfg(feature = "openssl")]
use certs::sev::builtin as SevBuiltin;

#[cfg(feature = "openssl")]
use std::convert::TryFrom;
use std::io::{Read, Write};

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

#[cfg(feature = "openssl")]
impl From<Generation> for CertSevCaChain {
    fn from(generation: Generation) -> CertSevCaChain {
        use codicon::Decoder;

        let (ark, ask) = match generation {
            Generation::Naples => (SevBuiltin::naples::ARK, SevBuiltin::naples::ASK),
            Generation::Rome => (SevBuiltin::rome::ARK, SevBuiltin::rome::ASK),
            Generation::Milan => (SevBuiltin::milan::ARK, SevBuiltin::milan::ASK),
            Generation::Genoa => (SevBuiltin::genoa::ARK, SevBuiltin::genoa::ASK),
        };

        CertSevCaChain {
            ask: Certificate::decode(&mut &*ask, ()).unwrap(),
            ark: Certificate::decode(&mut &*ark, ()).unwrap(),
        }
    }
}

#[cfg(feature = "openssl")]
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
