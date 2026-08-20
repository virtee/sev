// SPDX-License-Identifier: Apache-2.0

//! RATS Reference Value Provider: offline expected measurements and launch material.
//!
//! Guest owners use this module to compute **reference values** before launch —
//! digests, hash tables, and ID blocks that firmware and attestation reports
//! should match later. Nothing here collects guest evidence or verifies reports;
//! see [`crate::attestation::attester`] and [`crate::attestation::verifier`].
//!
//! Wire types for offline reference measurement live in
//! [`crate::types::shared::reference`].
//!
//! # Module layout
//!
//! | Module | Role | Used by |
//! |--------|------|---------|
//! | [`digest`] | SHA-256 / SHA-384 helpers (crypto backend–agnostic) | [`sev_hashes`], [`snp::measurement`](snp::measurement), [`snp::idblock`](snp::idblock) |
//! | [`sev_hashes`] | OVMF SEV-HASHES table for kernel/initrd/cmdline | [`snp::measurement`](snp::measurement), [`sev::measurement`](sev::measurement) |
//! | [`snp`] | SNP launch digest + ID block reference values | Guest owners launching SNP VMs |
//! | [`sev`] | Legacy SEV / SEV-ES launch digest (`crypto-openssl`) | Guest owners launching pre-SNP guests |
//!
//! # SNP workflow (typical)
//!
//! ```text
//!  sev_hashes::SevHashes  ──┐
//!                            ├──► snp::snp_calc_launch_digest() ──► expected measurement
//!  OVMF + vCPU config  ─────┘              │
//!                                          ▼
//!                               snp::idblock::snp_calculate_id() ──► ID block material
//! ```
//!
//! Shared building blocks ([`digest`], [`sev_hashes`]) sit at this level so both
//! SNP and legacy SEV measurement paths reuse the same hash primitives and QEMU-
//! compatible kernel hash table layout.
//!
//! # Features
//!
//! | Module | Required features |
//! |--------|-------------------|
//! | [`digest`], [`sev_hashes`] | `reference` + (`crypto-openssl` or `crypto-rust`) + (`snp` or `sev`) |
//! | [`snp`] | `reference` + `snp` + (`crypto-openssl` or `crypto-rust`); ID block needs `crypto-openssl` |
//! | [`sev`] | `reference` + `sev` + `crypto-openssl` |

#[cfg(all(
    any(feature = "sev", feature = "snp"),
    any(feature = "crypto-openssl", feature = "crypto-rust")
))]
pub mod digest;

#[cfg(all(
    any(feature = "sev", feature = "snp"),
    any(feature = "crypto-openssl", feature = "crypto-rust")
))]
pub mod sev_hashes;

#[cfg(all(
    feature = "snp",
    any(feature = "crypto-openssl", feature = "crypto-rust")
))]
pub mod snp;

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
pub mod sev;
