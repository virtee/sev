// SPDX-License-Identifier: Apache-2.0

//! Everything one needs to calculate a launch measurement for a SEV encrypted confidential guest.
//!
//! This module contains the structures and functions needed to calculate a launch measurement.
//! This includes, GCTX, SEV-HASHES, VMSA and OVMF pages.

///
#[cfg(all(any(feature = "sev", feature = "snp"), feature = "openssl"))]
pub mod gctx;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod ovmf;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod vmsa;

#[cfg(all(any(feature = "sev", feature = "snp"), feature = "openssl"))]
pub mod sev_hashes;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod vcpu_types;

#[cfg(all(any(feature = "sev", feature = "snp"), feature = "openssl"))]
pub mod measurement_functions;
