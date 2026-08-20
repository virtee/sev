// SPDX-License-Identifier: Apache-2.0

//! SNP launch digest (GCTX) reference value calculation.
//!
//! Guest owners use this module to **pre-compute** the SNP launch digest
//! (48-byte SHA-384 measurement) offline. The result is typically placed in an
//! [`IdBlock`](crate::types::snp::IdBlock) via
//! [`crate::attestation::reference::snp::idblock::snp_calculate_id`].
//!
//! # Terminology
//!
//! In this crate, **launch digest** and **expected measurement** refer to the
//! same value: the 48-byte guest launch measurement computed by the GCTX
//! algorithm. Naming differs by context:
//!
//! | Context | Name | Type / field |
//! |---------|------|--------------|
//! | Measurement APIs (this module) | launch digest | [`SnpLaunchDigest`] return value |
//! | ID block at launch | launch digest | [`IdBlock::launch_digest`] |
//! | Attestation report (after boot) | measurement | [`ReportBody::measurement`] |
//!
//! Use [`snp_calc_launch_digest`] to produce the **expected measurement** for a
//! guest configuration, store it in the ID block, and later compare it to the
//! `measurement` field in a verified attestation report.
//!
//! # Wire types
//!
//! OVMF parsing, vCPU selection, and VMSA construction use
//! [`crate::types::shared::reference`].
//!
//! # Launch digest flow
//!
//! ```text
//!  OVMF firmware ──► calc_snp_ovmf_hash() ──► partial LD (OVMF pages only)
//!                           │
//!  + kernel/initrd/append ──┼──► snp_calc_launch_digest() ──► full LD
//!  + vCPU count/type        │         (metadata + VMSA pages)
//!  + guest features         │
//!                           ▼
//!                    SnpLaunchDigest (48 bytes)
//!                           │
//!                           └──► IdBlock::launch_digest (expected measurement)
//! ```
//!
//! # Public API
//!
//! | Function | Use when |
//! |----------|----------|
//! | [`calc_snp_ovmf_hash`] | You only need the OVMF firmware portion of the digest |
//! | [`snp_calc_launch_digest`] | You need the full launch digest (OVMF + metadata + kernel + vCPUs) |
//!
//! [`SnpMeasurementArgs`] configures the full calculation. Pass a pre-computed
//! OVMF hash via [`SnpMeasurementArgs::ovmf_hash_str`] to skip re-hashing the
//! firmware blob when iterating on kernel or vCPU settings.
//!
//! # Example
//!
//! ```ignore
//! use sev::{
//!     attestation::reference::snp::{
//!         calc_snp_ovmf_hash,
//!         snp_calc_launch_digest,
//!         SnpMeasurementArgs,
//!     },
//!     types::shared::reference::vcpu::CpuType,
//!     types::shared::reference::vmsa::GuestFeatures,
//! };
//! use std::path::PathBuf;
//!
//! // OVMF-only digest
//! let ovmf_ld = calc_snp_ovmf_hash(PathBuf::from("OVMF.fd"))?;
//!
//! // Full guest launch digest
//! let ld = snp_calc_launch_digest(SnpMeasurementArgs {
//!     vcpus: 1,
//!     vcpu_type: CpuType::EpycV4,
//!     ovmf_file: PathBuf::from("OVMF.fd"),
//!     guest_features: GuestFeatures(0x1),
//!     kernel_file: Some(PathBuf::from("vmlinuz")),
//!     initrd_file: None,
//!     append: Some("console=ttyS0"),
//!     ovmf_hash_str: None,
//!     vmm_type: None,
//! })?;
//! ```
//!
//! # Internal modules
//!
//! | Module | Role |
//! |--------|------|
//! | `gctx` | GCTX state machine — folds each measured page into the launch digest |
//! | `update` | OVMF SEV metadata section → GCTX page updates |
//!
//! # Errors
//!
//! Returns [`MeasurementError`](crate::error::MeasurementError) for invalid OVMF
//! layout, missing metadata sections, bad vCPU configuration, or GCTX update
//! failures.

mod gctx;
mod update;

use crate::{
    attestation::reference::sev_hashes::SevHashes,
    error::*,
    types::shared::reference::{
        ovmf::OVMF,
        vcpu::CpuType,
        vmsa::{GuestFeatures, VMMType, VMSA},
    },
    types::snp::{PageType, SnpLaunchDigest},
};
use hex::FromHex;
use std::path::PathBuf;

use self::gctx::{Gctx, Updating, VMSA_GPA};
use self::update::update_metadata_pages;

/// Inputs for [`snp_calc_launch_digest`].
pub struct SnpMeasurementArgs<'a> {
    /// Number of virtual CPUs to measure (drives VMSA page count).
    pub vcpus: u32,
    /// CPU model used to build each VMSA page ([`CpuType`]).
    pub vcpu_type: CpuType,
    /// Path to the OVMF firmware image (must contain AMD SEV metadata).
    pub ovmf_file: PathBuf,
    /// Active guest features encoded into each VMSA ([`GuestFeatures`]).
    pub guest_features: GuestFeatures,
    /// Path to the guest kernel image. When set, kernel/initrd/append hashes
    /// are built and the OVMF `SNP_KERNEL_HASHES` section is required.
    pub kernel_file: Option<PathBuf>,
    /// Optional initrd passed to [`SevHashes`](crate::attestation::reference::sev_hashes::SevHashes).
    pub initrd_file: Option<PathBuf>,
    /// Optional kernel command line appended to the hash table.
    pub append: Option<&'a str>,
    /// Pre-computed OVMF launch digest as lowercase hex (48 bytes / 96 hex chars).
    ///
    /// When set, skips re-measuring the OVMF blob and seeds GCTX from this value.
    /// Obtain with [`calc_snp_ovmf_hash`].
    pub ovmf_hash_str: Option<&'a str>,
    /// Hypervisor flavor affecting CPUID measurement order. Defaults to QEMU.
    pub vmm_type: Option<VMMType>,
}

/// Compute the launch digest contributed by the OVMF firmware image alone.
///
/// Measures the OVMF blob at its firmware GPA as a single normal page chain.
/// This is the first step in launch digest calculation and matches what
/// [`snp_calc_launch_digest`] performs internally when
/// [`SnpMeasurementArgs::ovmf_hash_str`] is `None`.
///
/// # Arguments
///
/// * `ovmf_file` — path to an OVMF binary with AMD SEV/SNP metadata.
///
/// # Returns
///
/// 48-byte [`SnpLaunchDigest`] covering only the OVMF portion of the **expected
/// measurement** (launch digest).
///
/// # Errors
///
/// [`MeasurementError`](crate::error::MeasurementError) if the file cannot be
/// read, OVMF metadata is invalid, or a GCTX page update fails.
///
/// # Example
///
/// ```ignore
/// let ld = calc_snp_ovmf_hash(PathBuf::from("OVMF.fd"))?;
/// ```
pub fn calc_snp_ovmf_hash(ovmf_file: PathBuf) -> Result<SnpLaunchDigest, MeasurementError> {
    let ovmf = OVMF::new(ovmf_file)?;
    let mut gctx = Gctx::default();

    gctx.update_page(PageType::Normal, ovmf.gpa(), Some(ovmf.data()), None)?;

    Ok(gctx.finished().ld())
}

/// Compute the full SNP guest launch digest.
///
/// Simulates firmware GCTX updates for:
///
/// 1. OVMF firmware pages (or seeds from [`SnpMeasurementArgs::ovmf_hash_str`])
/// 2. OVMF SEV metadata sections (secrets, CPUID, kernel hash table, etc.)
/// 3. One VMSA page per vCPU
///
/// The result is the full **expected measurement** (launch digest) for the
/// guest — the value stored in
/// [`IdBlock::launch_digest`](crate::types::snp::IdBlock::launch_digest) and
/// compared against [`ReportBody::measurement`](crate::attestation::evidence::snp::ReportBody::measurement)
/// after attestation.
///
/// # Arguments
///
/// * `snp_measurement` — launch configuration ([`SnpMeasurementArgs`]).
///
/// # Returns
///
/// 48-byte [`SnpLaunchDigest`] — the launch digest / expected measurement for
/// the complete guest as configured.
///
/// # Errors
///
/// * OVMF / kernel file I/O or parse failures
/// * [`MeasurementError::MissingSection`] when kernel hashes are requested but
///   OVMF lacks `SNP_KERNEL_HASHES`
/// * Invalid pre-seeded OVMF hash hex in `ovmf_hash_str`
/// * VMSA generation failures (invalid vCPU count/type)
///
/// # Example
///
/// See the [module-level example](crate::attestation::reference::snp::measurement).
pub fn snp_calc_launch_digest(
    snp_measurement: SnpMeasurementArgs,
) -> Result<SnpLaunchDigest, MeasurementError> {
    let ovmf = OVMF::new(snp_measurement.ovmf_file)?;

    let mut gctx: Gctx<Updating> = match snp_measurement.ovmf_hash_str {
        Some(hash) => {
            let ovmf_hash = Vec::from_hex(hash)?;
            Gctx::new(ovmf_hash.as_slice())?
        }
        None => {
            let mut gctx = Gctx::default();
            gctx.update_page(PageType::Normal, ovmf.gpa(), Some(ovmf.data()), None)?;
            gctx
        }
    };

    let sev_hashes = match snp_measurement.kernel_file {
        Some(kernel) => Some(SevHashes::new(
            kernel,
            snp_measurement.initrd_file,
            snp_measurement.append,
        )?),
        None => None,
    };

    let vmm_type = snp_measurement.vmm_type.unwrap_or(VMMType::QEMU);

    update_metadata_pages(&mut gctx, &ovmf, sev_hashes.as_ref(), vmm_type)?;

    let vmsa = VMSA::new(
        ovmf.sev_es_reset_eip()?.into(),
        snp_measurement.vcpu_type,
        vmm_type,
        Some(snp_measurement.vcpus as u64),
        snp_measurement.guest_features,
    );

    for vmsa_page in vmsa.pages(snp_measurement.vcpus as usize)?.iter() {
        gctx.update_page(PageType::Vmsa, VMSA_GPA, Some(vmsa_page.as_slice()), None)?
    }

    Ok(gctx.finished().ld())
}
