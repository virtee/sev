// SPDX-License-Identifier: Apache-2.0

//! SNP reference values for guest launch and attestation appraisal.
//!
//! Implements the RATS **Reference Value Provider** role for SEV-SNP. Guest
//! owners use these APIs offline to compute values they expect firmware and
//! attestation reports to match — nothing here runs inside the guest or
//! verifies evidence at runtime.
//!
//! # Wire types
//!
//! OVMF parsing, vCPU selection, and VMSA construction use
//! [`crate::types::shared::reference`].
//!
//! # Submodules
//!
//! | Module | Purpose | Main APIs |
//! |--------|---------|-----------|
//! | [`measurement`] | Expected guest measurement (launch digest) | [`calc_snp_ovmf_hash`], [`snp_calc_launch_digest`] |
//! | [`idblock`] (`crypto-openssl`) | ID block + AUTH block + key digests | [`idblock::snp_calculate_id`] |
//!
//! [`measurement`] functions are re-exported at this module root (`calc_snp_ovmf_hash`,
//! `snp_calc_launch_digest`, `SnpMeasurementArgs`). ID block functions live
//! under [`idblock`] because they require OpenSSL.
//!
//! # End-to-end workflow
//!
//! ```text
//!  1. measurement::snp_calc_launch_digest()
//!         │
//!         ▼
//!     SnpLaunchDigest  (= expected measurement)
//!         │
//!  2. idblock::snp_calculate_id(launch_digest, …)
//!         │
//!         ▼
//!     IdMeasurements { id_block, id_auth, id_key_digest, auth_key_digest }
//!         │
//!         ▼
//!     Guest launch (firmware ioctls / QEMU)
//!         │
//!         ▼
//!  3. attester + verifier — compare report fields to reference values
//! ```
//!
//! # Terminology
//!
//! **Launch digest** and **expected measurement** are the same 48-byte GCTX
//! value. See [`measurement`] for the full naming table across ID blocks and
//! attestation reports.
//!
//! # Example
//!
//! ```ignore
//! use sev::{
//!     attestation::reference::snp::{
//!         calc_snp_ovmf_hash,
//!         idblock::snp_calculate_id,
//!         snp_calc_launch_digest,
//!         SnpMeasurementArgs,
//!     },
//!     types::shared::reference::{vcpu::CpuType, vmsa::GuestFeatures},
//! };
//! use std::path::PathBuf;
//!
//! // Step 1: expected measurement
//! let ld = snp_calc_launch_digest(SnpMeasurementArgs {
//!     vcpus: 1,
//!     vcpu_type: CpuType::EpycV4,
//!     ovmf_file: PathBuf::from("OVMF.fd"),
//!     guest_features: GuestFeatures(0x1),
//!     kernel_file: Some(PathBuf::from("vmlinuz")),
//!     initrd_file: None,
//!     append: None,
//!     ovmf_hash_str: None,
//!     vmm_type: None,
//! })?;
//!
//! // Step 2: ID block material (requires crypto-openssl)
//! let id = snp_calculate_id(
//!     Some(ld),
//!     None,
//!     None,
//!     None,
//!     None,
//!     PathBuf::from("id-key.pem"),
//!     PathBuf::from("author-key.pem"),
//! )?;
//! ```
//!
//! # Features
//!
//! * `reference` + `snp` — always required
//! * [`measurement`] — always available with `reference`
//! * [`idblock`] — additionally requires `crypto-openssl`

#[cfg(feature = "crypto-openssl")]
pub mod idblock;

pub mod measurement;

pub use measurement::*;
