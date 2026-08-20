// SPDX-License-Identifier: Apache-2.0

//! Legacy SEV launch attestation report wire type.

const MNONCE_SIZE: usize = 128 / 8;
const DIGEST_SIZE: usize = 256 / 8;
const POLICY_SIZE: usize = 32 / 8;
const POLICY_OFFSET: usize = MNONCE_SIZE + DIGEST_SIZE;
const MEASURABLE_BYTES: usize = MNONCE_SIZE + DIGEST_SIZE + POLICY_SIZE;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use serde_big_array::BigArray;

/// An attestation report structure.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    pub signature: [u8; 144], // 0x40 - 0xCF
}

impl Default for LegacyAttestationReport {
    fn default() -> Self {
        Self {
            mnonce: Default::default(),
            launch_digest: Default::default(),
            policy: Default::default(),
            sig_usage: Default::default(),
            sig_algo: Default::default(),
            _reserved_0: Default::default(),
            signature: [0u8; 144],
        }
    }
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
