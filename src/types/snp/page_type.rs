// SPDX-License-Identifier: Apache-2.0

//! SNP launch-update page types (firmware Table 58).
//!
//! Tags guest pages during SNP launch and reference measurement. Each variant
//! tells the PSP how to treat a 4 KiB page when updating the launch digest.
//!
//! # Consumers
//!
//! | Module | Role |
//! |--------|------|
//! | [`crate::launch`] | Pass page type to KVM launch-update ioctls at runtime |
//! | [`crate::attestation::reference::snp::measurement`] | Reproduce the same page updates offline |
//!
//! # Variants
//!
//! - [`Normal`](Self::Normal) — measured data page (OVMF, kernel hash table, …)
//! - [`Vmsa`](Self::Vmsa) — measured vCPU VMSA page
//! - [`Zero`](Self::Zero) — measured as zero-filled
//! - [`Unmeasured`](Self::Unmeasured) — encrypted but not measured
//! - [`Secrets`](Self::Secrets) — firmware secrets page
//! - [`Cpuid`](Self::Cpuid) — hypervisor-provided CPUID values

/// Encoded page type for an SNP launch update (firmware Table 58).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
#[non_exhaustive]
pub enum PageType {
    /// A normal data page.
    Normal = 0x1,

    /// A VMSA page.
    Vmsa = 0x2,

    /// A page full of zeroes.
    Zero = 0x3,

    /// A page that is encrypted but not measured.
    Unmeasured = 0x4,

    /// A page for the firmware to store secrets for the guest.
    Secrets = 0x5,

    /// A page for the hypervisor to provide CPUID function values.
    Cpuid = 0x6,
}
