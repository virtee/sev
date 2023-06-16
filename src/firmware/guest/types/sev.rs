// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use std::convert::TryInto;

use crate::certs::snp::ecdsa::Signature;

#[cfg(feature = "openssl")]
use crate::certs::sev::{
    sev::{Certificate, Usage},
    PublicKey, Verifiable,
};

#[cfg(feature = "openssl")]
use openssl::{ec::EcKey, ecdsa::EcdsaSig, pkey::Public};
use serde::{Deserialize, Serialize};

const MNONCE_SIZE: usize = 128 / 8;
const DIGEST_SIZE: usize = 256 / 8;
const POLICY_SIZE: usize = 32 / 8;
const POLICY_OFFSET: usize = MNONCE_SIZE + DIGEST_SIZE;
const MEASURABLE_BYTES: usize = MNONCE_SIZE + DIGEST_SIZE + POLICY_SIZE;

/// An attestation report structure.
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct LegacyAttestationReport {
    /// 128-bit Nonce from the Command Buffer.
    pub mnonce: [u8; MNONCE_SIZE], // 0x00
    /// SHA-256 digest of launched guest.
    pub launch_digest: [u8; POLICY_SIZE], // 0x10
    /// Policy guest was launched with.
    pub policy: u32, // 0x30
    /// Key usage of SIG1 signing key.
    pub sig_usage: u32, // 0x34
    /// Signature Algorithm
    pub sig_algo: u32, // 0x38
    /// Reserved
    _reserved_0: u32, // 0x3C
    /// Signature of the report.
    // #[serde(with = "BigArray")]
    // pub signature: [u8; 144], // 0x40 - 0xCF
    pub signature: Signature,
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

        sig.verify(&self.1.measurable_bytes(), pub_key)?;

        Ok(())
    }
}
