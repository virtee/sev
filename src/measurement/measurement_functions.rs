// SPDX-License-Identifier: Apache-2.0

//! Operations to calculate guest measurement for different SEV modes
use crate::measurement::{
    gctx::Gctx,
    ovmf::{OvmfSevMetadataSectionDesc, SectionType, OVMF},
    sev_hashes::SevHashes,
    vcpu_types::CpuType,
    vmsa::{SevMode, VMMType, VMSA},
};
use hex::FromHex;
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::*;

use openssl::sha::Sha256;

const _PAGE_MASK: u64 = 0xfff;

/// Get the launch digest as a hex string
pub fn get_hex_ld(ld: Vec<u8>) -> String {
    hex::encode(ld)
}

/// Update launch digest with SEV kernel hashes
fn snp_update_kernel_hashes(
    gctx: &mut Gctx,
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
            gctx.update_normal_pages(gpa, sev_hashes_page.as_slice())?
        }
        None => gctx.update_zero_pages(gpa, size)?,
    }

    Ok(())
}

/// Update launch digest with different section types
fn snp_update_section(
    desc: &OvmfSevMetadataSectionDesc,
    gctx: &mut Gctx,
    ovmf: &OVMF,
    sev_hashes: Option<&SevHashes>,
    vmm_type: VMMType,
) -> Result<(), MeasurementError> {
    match desc.section_type {
        SectionType::SnpSecMemory => gctx.update_zero_pages(desc.gpa.into(), desc.size as usize)?,
        SectionType::SnpSecrets => gctx.update_secrets_page(desc.gpa.into())?,
        SectionType::CPUID => {
            if vmm_type != VMMType::EC2 {
                gctx.update_cpuid_page(desc.gpa.into())?
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
    gctx: &mut Gctx,
    ovmf: &OVMF,
    sev_hashes: Option<&SevHashes>,
    vmm_type: VMMType,
) -> Result<(), MeasurementError> {
    for desc in ovmf.metadata_items().iter() {
        snp_update_section(desc, gctx, ovmf, sev_hashes, vmm_type)?
    }

    if vmm_type == VMMType::EC2 {
        for desc in ovmf.metadata_items() {
            if desc.section_type == SectionType::CPUID {
                gctx.update_cpuid_page(desc.gpa.into())?
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

/// Calculate the OVMF hash from OVMF file
pub fn calc_snp_ovmf_hash(ovmf_file: PathBuf) -> Result<[u8; 48], MeasurementError> {
    let ovmf = OVMF::new(ovmf_file)?;
    let mut gctx = Gctx::default();

    gctx.update_normal_pages(ovmf.gpa(), ovmf.data())?;

    Ok(gctx.get_ld())
}

/// Calulate an SEV-SNP launch digest
#[allow(clippy::too_many_arguments)]
pub fn snp_calc_launch_digest(
    vcpus: u32,
    vcpu_type: String,
    ovmf_file: PathBuf,
    kernel_file: Option<PathBuf>,
    initrd_file: Option<PathBuf>,
    append: Option<&str>,
    ovmf_hash_str: Option<&str>,
    vmm_type: Option<VMMType>,
) -> Result<[u8; 48], MeasurementError> {
    let ovmf = OVMF::new(ovmf_file)?;

    let mut gctx = match ovmf_hash_str {
        Some(hash) => {
            let ovmf_hash = Vec::from_hex(hash)?;
            Gctx::new(ovmf_hash.as_slice())
        }
        None => {
            let mut gctx = Gctx::default();

            gctx.update_normal_pages(ovmf.gpa(), ovmf.data())?;

            Ok(gctx)
        }
    }?;

    let sev_hashes = match kernel_file {
        Some(kernel) => Some(SevHashes::new(kernel, initrd_file, append)?),
        None => None,
    };

    let official_vmm_type = match vmm_type {
        Some(vmm) => vmm,
        None => VMMType::QEMU,
    };

    snp_update_metadata_pages(&mut gctx, &ovmf, sev_hashes.as_ref(), official_vmm_type)?;

    let vmsa = VMSA::new(
        SevMode::SevSnp,
        ovmf.sev_es_reset_eip()?.into(),
        CpuType::from_str(vcpu_type.as_str())?,
        official_vmm_type,
        Some(vcpus as u64),
    );

    for vmsa_page in vmsa.pages(vcpus as usize)?.iter() {
        gctx.update_vmsa_page(vmsa_page.as_slice())?
    }

    Ok(gctx.get_ld())
}

/// Calculate an SEV-ES launch digest
pub fn seves_calc_launch_digest(
    vcpus: u32,
    vcpu_type: String,
    ovmf_file: PathBuf,
    kernel_file: Option<PathBuf>,
    initrd_file: Option<PathBuf>,
    append: Option<&str>,
    vmm_type: Option<VMMType>,
) -> Result<[u8; 32], MeasurementError> {
    let ovmf = OVMF::new(ovmf_file)?;
    let mut launch_hash = Sha256::new();
    launch_hash.update(ovmf.data().as_slice());

    if let Some(kernel) = kernel_file {
        if !ovmf.is_sev_hashes_table_supported() {
            return Err(MeasurementError::KernelSpecifiedError);
        }
        let sev_hashes = SevHashes::new(kernel, initrd_file, append)?.construct_table()?;
        launch_hash.update(sev_hashes.as_slice());
    };

    let official_vmm_type = match vmm_type {
        Some(vmm) => vmm,
        None => VMMType::QEMU,
    };

    let vmsa = VMSA::new(
        SevMode::SevEs,
        ovmf.sev_es_reset_eip()?.into(),
        CpuType::from_str(vcpu_type.as_str())?,
        official_vmm_type,
        Some(vcpus as u64),
    );

    for vmsa_page in vmsa.pages(vcpus as usize)?.iter() {
        launch_hash.update(vmsa_page.as_slice())
    }

    Ok(launch_hash.finish())
}

/// Calculate an SEV launch digest
pub fn sev_calc_launch_digest(
    ovmf_file: PathBuf,
    kernel_file: Option<PathBuf>,
    initrd_file: Option<PathBuf>,
    append: Option<&str>,
) -> Result<[u8; 32], MeasurementError> {
    let ovmf = OVMF::new(ovmf_file)?;
    let mut launch_hash = Sha256::new();
    launch_hash.update(ovmf.data().as_slice());

    if let Some(kernel) = kernel_file {
        if !ovmf.is_sev_hashes_table_supported() {
            return Err(MeasurementError::KernelSpecifiedError);
        }
        let sev_hashes = SevHashes::new(kernel, initrd_file, append)?.construct_table()?;
        launch_hash.update(sev_hashes.as_slice());
    };

    Ok(launch_hash.finish())
}
