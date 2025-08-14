// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

use crate::firmware::host::State;
pub use crate::firmware::linux::host::types::PlatformStatusFlags;
use crate::util::{array::Array, TypeLoad, TypeSave};
use crate::{Decoder, Encoder};

#[cfg(feature = "openssl")]
use std::convert::TryInto;

#[cfg(feature = "openssl")]
use crate::certs::sev::{
    sev::{Certificate, Usage},
    PublicKey, Verifiable,
};

#[cfg(feature = "openssl")]
use openssl::{ec::EcKey, ecdsa::EcdsaSig, pkey::Public, sha::Sha256};

use serde::{Deserialize, Serialize};

use std::{
    fmt::Debug,
    io::{Read, Write},
};

const MNONCE_SIZE: usize = 128 / 8;
const DIGEST_SIZE: usize = 256 / 8;
const POLICY_SIZE: usize = 32 / 8;
const POLICY_OFFSET: usize = MNONCE_SIZE + DIGEST_SIZE;
const MEASURABLE_BYTES: usize = MNONCE_SIZE + DIGEST_SIZE + POLICY_SIZE;

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

impl Decoder<()> for Build {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, _: ()) -> std::io::Result<Self> {
        reader.load()
    }
}

impl Encoder<()> for Build {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.save(self)
    }
}

/// Information regarding the SEV platform's current status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The build number.
    pub build: Build,

    /// The platform's current state.
    pub state: State,

    /// Additional platform information is encoded into flags.
    ///
    /// These could describe whether encrypted state functionality
    /// is enabled, or whether the platform is self-owned.
    pub flags: PlatformStatusFlags,

    /// The number of valid guests supervised by this platform.
    pub guests: u32,
}

/// An attestation report structure.
#[derive(Default, Serialize, Deserialize)]
#[repr(C)]
pub struct LegacyAttestationReport {
    /// 128-bit Nonce from the Command Buffer.
    pub mnonce: [u8; MNONCE_SIZE], // 0x00
    /// SHA-256 digest of launched guest.
    pub launch_digest: [u8; DIGEST_SIZE], // 0x10
    /// Policy guest was launched with.
    pub policy: u32, // 0x30
    /// Key usage of SIG1 signing key.
    pub sig_usage: u32, // 0x34
    /// Signature Algorithm
    pub sig_algo: u32, // 0x38
    /// Reserved
    _reserved_0: u32, // 0x3C
    /// Signature of the report.
    pub signature: Array<u8, 144>, // 0x40 - 0xCF
}

impl LegacyAttestationReport {
    /// Provides the measured bytes of the report. This should include bits 0x0 - 0x34 inclusively.
    pub fn measurable_bytes(&self) -> [u8; MEASURABLE_BYTES] {
        let mut bytes: [u8; MEASURABLE_BYTES] = [0; 52];
        bytes[0..MNONCE_SIZE].copy_from_slice(&self.mnonce);
        bytes[MNONCE_SIZE..POLICY_OFFSET].copy_from_slice(&self.launch_digest);
        bytes[POLICY_OFFSET..].copy_from_slice(&self.policy.to_ne_bytes());
        bytes
    }
}

#[cfg(feature = "openssl")]
impl Verifiable for (&Certificate, &LegacyAttestationReport) {
    type Output = ();

    fn verify(self) -> std::io::Result<Self::Output> {
        let sev_pub_key: PublicKey<Usage> = self.0.try_into()?;
        let pub_key: &EcKey<Public> = &sev_pub_key.ec_key()?;

        let sig: EcdsaSig = (&self.1.signature).try_into()?;

        let mut hasher = Sha256::new();
        hasher.update(&self.1.measurable_bytes());
        let base_digest = hasher.finish();

        let signed = sig.verify(&base_digest, pub_key)?;
        match signed {
            true => Ok(()),
            false => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "PEK does not sign the attestation report",
            )),
        }
    }
}
