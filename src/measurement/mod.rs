// SPDX-License-Identifier: Apache-2.0

//! Everything one needs to calculate a launch measurement for a SEV encrypted confidential guest.
//! This includes, GCTX, SEV-HASHES, VMSA and OVMF pages.

#[cfg(all(target_os = "linux", feature = "snp", feature = "openssl"))]
pub mod gctx;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod ovmf;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod vmsa;

#[cfg(all(any(feature = "sev", feature = "snp"), feature = "openssl"))]
pub mod sev_hashes;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod vcpu_types;

#[cfg(all(feature = "snp", feature = "openssl"))]
pub mod snp;

#[cfg(all(feature = "sev", feature = "openssl"))]
pub mod sev;

#[cfg(all(feature = "snp", feature = "openssl"))]
pub mod idblock;

#[cfg(all(feature = "snp", feature = "openssl"))]
pub mod idblock_types;
