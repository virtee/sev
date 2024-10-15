// SPDX-License-Identifier: Apache-2.0

//! SEV and SEV-SNP shared types for interacting with the KVM SEV guest management API.

/// Structure passed into KVM_SEV_INIT2 command.
#[derive(Default)]
#[repr(C, packed)]
pub struct Init2 {
    /// Initial value of features field in VMSA. (Must be 0 for SEV)
    vmsa_features: u64,

    /// Always set to 0
    flags: u32,

    /// Maximum guest GHCB version allowed. (Currently 0 for SEV and 1 for SEV-ES and SEV-SNP)
    ghcb_version: u16,

    pad1: u16,

    pad2: [u32; 8],
}

impl Init2 {
    /// Default INIT2 values for SEV
    #[cfg(feature = "sev")]
    pub fn init_default_sev() -> Self {
        Self {
            vmsa_features: 0,
            flags: 0,
            ghcb_version: 0,
            pad1: Default::default(),
            pad2: Default::default(),
        }
    }

    /// Default INIT2 values for SEV-ES
    #[cfg(feature = "sev")]
    pub fn init_default_es() -> Self {
        Self {
            vmsa_features: 0x1,
            flags: 0,
            ghcb_version: 1,
            pad1: Default::default(),
            pad2: Default::default(),
        }
    }

    /// Default INIT2 values for SEV-SNP
    #[cfg(feature = "snp")]
    pub fn init_default_snp() -> Self {
        Self {
            vmsa_features: 0,
            flags: 0,
            ghcb_version: 2,
            pad1: Default::default(),
            pad2: Default::default(),
        }
    }
}
