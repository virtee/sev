// SPDX-License-Identifier: Apache-2.0

//! OVMF SEV metadata → GCTX page updates.
//!
//! Maps entries from the OVMF AMD SEV metadata table to [`Gctx::update_page`]
//! calls so [`super::snp_calc_launch_digest`] reproduces the same expected
//! measurement firmware would compute after OVMF pages are loaded.
//!
//! Called from [`super::snp_calc_launch_digest`] after the OVMF blob (or a
//! pre-seeded OVMF hash) has been measured. Not part of the public API.
//!
//! # Metadata section mapping
//!
//! | [`SectionType`] | GCTX update |
//! |-----------------|-------------|
//! | `SnpSecMemory` | [`PageType::Zero`] span at section GPA |
//! | `SnpSecrets` | [`PageType::Secrets`] at section GPA |
//! | `Cpuid` | [`PageType::Cpuid`] at section GPA (order depends on [`VMMType`]) |
//! | `SnpKernelHashes` | [`PageType::Normal`] hash table page or [`PageType::Zero`] fallback |
//! | `SvsmCaa` | [`PageType::Zero`] span at section GPA |
//!
//! # VMM differences
//!
//! * **QEMU (default)** — CPUID sections are measured during the main metadata walk.
//! * **EC2** — CPUID sections are measured in a second pass after all other sections.

use super::gctx::{Gctx, Updating};

use crate::{
    attestation::reference::sev_hashes::SevHashes,
    error::MeasurementError,
    types::shared::reference::{
        ovmf::{OvmfSevMetadataSectionDesc, SectionType, OVMF},
        vmsa::VMMType,
    },
    types::snp::PageType,
};

/// Mask for the in-page offset of the SEV hashes table GPA.
const PAGE_MASK: u64 = 0xfff;

/// Measure the OVMF `SNP_KERNEL_HASHES` metadata region.
///
/// When [`SevHashes`] is present (kernel/initrd/append were supplied), builds
/// the hash table page at the GPA encoded in OVMF metadata and measures it as
/// [`PageType::Normal`]. Otherwise measures the region as zero-filled
/// ([`PageType::Zero`]).
///
/// # Arguments
///
/// * `gctx` — guest context to update
/// * `ovmf` — parsed OVMF (provides hash-table GPA for page layout)
/// * `sev_hashes` — optional kernel hash table from [`SevHashes::new`](crate::attestation::reference::sev_hashes::SevHashes::new)
/// * `gpa` / `size` — GPA and byte length from the metadata section descriptor
pub(crate) fn update_kernel_hashes(
    gctx: &mut Gctx<Updating>,
    ovmf: &OVMF,
    sev_hashes: Option<&SevHashes>,
    gpa: u64,
    size: usize,
) -> Result<(), MeasurementError> {
    match sev_hashes {
        Some(hash) => {
            let sev_hashes_table_gpa = ovmf.sev_hashes_table_gpa()?;
            let page_offset = sev_hashes_table_gpa & PAGE_MASK;
            let sev_hashes_page = hash.construct_page(page_offset as usize)?;
            assert_eq!(sev_hashes_page.len(), size);
            gctx.update_page(
                PageType::Normal,
                gpa,
                Some(sev_hashes_page.as_slice()),
                None,
            )?
        }
        None => gctx.update_page(PageType::Zero, gpa, None, Some(size))?,
    }

    Ok(())
}

/// Measure one OVMF SEV metadata section.
///
/// Dispatches on [`OvmfSevMetadataSectionDesc::section_type`] to the appropriate
/// [`Gctx::update_page`] call. CPUID sections are skipped on the first pass
/// when `vmm_type` is [`VMMType::EC2`] (handled later by
/// [`update_metadata_pages`]).
pub(crate) fn update_section(
    desc: &OvmfSevMetadataSectionDesc,
    gctx: &mut Gctx<Updating>,
    ovmf: &OVMF,
    sev_hashes: Option<&SevHashes>,
    vmm_type: VMMType,
) -> Result<(), MeasurementError> {
    match desc.section_type {
        SectionType::SnpSecMemory => gctx.update_page(
            PageType::Zero,
            desc.gpa.into(),
            None,
            Some(desc.size as usize),
        )?,
        SectionType::SnpSecrets => {
            gctx.update_page(PageType::Secrets, desc.gpa.into(), None, None)?
        }
        SectionType::Cpuid => {
            if vmm_type != VMMType::EC2 {
                gctx.update_page(PageType::Cpuid, desc.gpa.into(), None, None)?
            }
        }
        SectionType::SnpKernelHashes => {
            update_kernel_hashes(gctx, ovmf, sev_hashes, desc.gpa.into(), desc.size as usize)?
        }
        SectionType::SvsmCaa => gctx.update_page(
            PageType::Zero,
            desc.gpa.into(),
            None,
            Some(desc.size as usize),
        )?,
    }

    Ok(())
}

/// Measure all OVMF SEV metadata sections into the guest context.
///
/// Walks every descriptor from [`OVMF::metadata_items`], applies
/// [`update_section`], then performs VMM-specific post-processing.
///
/// # Arguments
///
/// * `gctx` — guest context (already contains OVMF page measurement)
/// * `ovmf` — parsed firmware with SEV metadata table
/// * `sev_hashes` — kernel hash table when a kernel file was provided
/// * `vmm_type` — hypervisor flavor ([`VMMType::QEMU`] or [`VMMType::EC2`])
///
/// # Errors
///
/// * Propagates errors from [`Gctx::update_page`] and hash table construction.
/// * [`MeasurementError::MissingSection`] when `sev_hashes` is `Some` but OVMF
///   lacks a `SNP_KERNEL_HASHES` metadata entry.
pub(crate) fn update_metadata_pages(
    gctx: &mut Gctx<Updating>,
    ovmf: &OVMF,
    sev_hashes: Option<&SevHashes>,
    vmm_type: VMMType,
) -> Result<(), MeasurementError> {
    for desc in ovmf.metadata_items().iter() {
        update_section(desc, gctx, ovmf, sev_hashes, vmm_type)?;
    }

    if vmm_type == VMMType::EC2 {
        for desc in ovmf.metadata_items() {
            if desc.section_type == SectionType::Cpuid {
                gctx.update_page(PageType::Cpuid, desc.gpa.into(), None, None)?
            }
        }
    }
    if sev_hashes.is_some() && !ovmf.has_metadata_section(SectionType::SnpKernelHashes) {
        return Err(MeasurementError::MissingSection(
            "SNP_KERNEL_HASHES".to_string(),
        ));
    }

    Ok(())
}
