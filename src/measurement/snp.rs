// SPDX-License-Identifier: Apache-2.0

//! Operations to calculate guest measurement for different SEV modes
use crate::{
    launch::snp::PageType,
    measurement::{
        gctx::{Gctx, Updating, VMSA_GPA},
        ovmf::{OvmfSevMetadataSectionDesc, SectionType, OVMF},
        sev_hashes::SevHashes,
        vcpu_types::CpuType,
        vmsa::{VMMType, VMSA},
    },
};
use hex::FromHex;
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::*;

use super::{gctx::LD_SIZE, vmsa::GuestFeatures};

const _PAGE_MASK: u64 = 0xfff;

/// Get the launch digest as a hex string
pub fn get_hex_ld(ld: Vec<u8>) -> String {
    hex::encode(ld)
}

/// Update launch digest with SEV kernel hashes
fn snp_update_kernel_hashes(
    gctx: &mut Gctx<Updating>,
    ovmf: &OVMF,
    sev_hashes: Option<&SevHashes>,
    gpa: u64,
    size: usize,
) -> Result<(), MeasurementError> {
    match sev_hashes {
        Some(hash) => {
            let sev_hashes_table_gpa = ovmf.sev_hashes_table_gpa()?;
            let page_offset = sev_hashes_table_gpa & _PAGE_MASK;
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

/// Update launch digest with different section types
fn snp_update_section(
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
        SectionType::CPUID => {
            if vmm_type != VMMType::EC2 {
                gctx.update_page(PageType::Cpuid, desc.gpa.into(), None, None)?
            }
        }
        SectionType::SnpKernelHashes => {
            snp_update_kernel_hashes(gctx, ovmf, sev_hashes, desc.gpa.into(), desc.size as usize)?
        }
    }

    Ok(())
}

/// Update GCTX with different metadata pages
fn snp_update_metadata_pages(
    gctx: &mut Gctx<Updating>,
    ovmf: &OVMF,
    sev_hashes: Option<&SevHashes>,
    vmm_type: VMMType,
) -> Result<(), MeasurementError> {
    for desc in ovmf.metadata_items().iter() {
        snp_update_section(desc, gctx, ovmf, sev_hashes, vmm_type)?;
    }

    if vmm_type == VMMType::EC2 {
        for desc in ovmf.metadata_items() {
            if desc.section_type == SectionType::CPUID {
                gctx.update_page(PageType::Cpuid, desc.gpa.into(), None, None)?
            }
        }
    }
    if sev_hashes.is_some() && !ovmf.has_metadata_section(SectionType::SnpKernelHashes) {
        return Err(MeasurementError::MissingSection(
            "SNP_KERNEL_HASHES".to_string(),
        ));
    };

    Ok(())
}

/// Calculate the OVMF hash from OVMF file
pub fn calc_snp_ovmf_hash(ovmf_file: PathBuf) -> Result<[u8; LD_SIZE], MeasurementError> {
    let ovmf = OVMF::new(ovmf_file)?;
    let mut gctx = Gctx::default();

    gctx.update_page(PageType::Normal, ovmf.gpa(), Some(ovmf.data()), None)?;

    let gctx = gctx.finished();

    Ok(*gctx.ld())
}

/// Arguments required to calculate the SNP measurement
pub struct SnpMeasurementArgs<'a> {
    /// Number of vcpus
    pub vcpus: u32,
    /// vcpu type
    pub vcpu_type: String,
    /// Path to OVMF file
    pub ovmf_file: PathBuf,
    /// Active kernel guest features
    pub guest_features: GuestFeatures,
    /// Path to kernel file
    pub kernel_file: Option<PathBuf>,
    /// Path to initrd file
    pub initrd_file: Option<PathBuf>,
    /// Append arguments for kernel
    pub append: Option<&'a str>,
    /// Already calculated ovmf hash
    pub ovmf_hash_str: Option<&'a str>,
    /// vmm type
    pub vmm_type: Option<VMMType>,
}

/// Calulate an SEV-SNP launch digest
pub fn snp_calc_launch_digest(
    snp_measurement: SnpMeasurementArgs,
) -> Result<[u8; LD_SIZE], MeasurementError> {
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

    let official_vmm_type = match snp_measurement.vmm_type {
        Some(vmm) => vmm,
        None => VMMType::QEMU,
    };

    snp_update_metadata_pages(&mut gctx, &ovmf, sev_hashes.as_ref(), official_vmm_type)?;

    let vmsa = VMSA::new(
        ovmf.sev_es_reset_eip()?.into(),
        CpuType::from_str(snp_measurement.vcpu_type.as_str())?,
        official_vmm_type,
        Some(snp_measurement.vcpus as u64),
        snp_measurement.guest_features,
    );

    for vmsa_page in vmsa.pages(snp_measurement.vcpus as usize)?.iter() {
        gctx.update_page(PageType::Vmsa, VMSA_GPA, Some(vmsa_page.as_slice()), None)?
    }

    let gctx = gctx.finished();

    Ok(*gctx.ld())
}
