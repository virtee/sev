// SPDX-License-Identifier: Apache-2.0

//! Operations to calculate guest measurement for different SEV modes
use crate::measurement::{
    ovmf::OVMF,
    sev_hashes::SevHashes,
    vcpu_types::CpuType,
    vmsa::{GuestFeatures, VMMType, VMSA},
};

use std::path::PathBuf;

use crate::error::*;

use openssl::sha::Sha256;

const _PAGE_MASK: u64 = 0xfff;

/// Get the launch digest as a hex string
pub fn get_hex_ld(ld: Vec<u8>) -> String {
    hex::encode(ld)
}

/// Arguments required to calculate the SEV-ES measurement
pub struct SevEsMeasurementArgs<'a> {
    /// Number of vcpus
    pub vcpus: u32,
    /// vcpu type
    pub vcpu_type: CpuType,
    /// Path to OVMF file
    pub ovmf_file: PathBuf,
    /// Path to kernel file
    pub kernel_file: Option<PathBuf>,
    /// Path to initrd file
    pub initrd_file: Option<PathBuf>,
    /// Append arguments for kernel
    pub append: Option<&'a str>,
    /// vmm type
    pub vmm_type: Option<VMMType>,
}

/// Calculate an SEV-ES launch digest
pub fn seves_calc_launch_digest(
    sev_es_measurement: SevEsMeasurementArgs,
) -> Result<[u8; 32], MeasurementError> {
    let ovmf = OVMF::new(sev_es_measurement.ovmf_file)?;
    let mut launch_hash = Sha256::new();
    launch_hash.update(ovmf.data().as_slice());

    if let Some(kernel) = sev_es_measurement.kernel_file {
        if !ovmf.is_sev_hashes_table_supported() {
            return Err(MeasurementError::InvalidOvmfKernelError);
        }
        let sev_hashes = SevHashes::new(
            kernel,
            sev_es_measurement.initrd_file,
            sev_es_measurement.append,
        )?
        .construct_table()?;
        launch_hash.update(sev_hashes.as_slice());
    };

    let official_vmm_type = match sev_es_measurement.vmm_type {
        Some(vmm) => vmm,
        None => VMMType::QEMU,
    };

    let vmsa = VMSA::new(
        ovmf.sev_es_reset_eip()?.into(),
        sev_es_measurement.vcpu_type,
        official_vmm_type,
        Some(sev_es_measurement.vcpus as u64),
        GuestFeatures(0x0),
    );

    for vmsa_page in vmsa.pages(sev_es_measurement.vcpus as usize)?.iter() {
        launch_hash.update(vmsa_page.as_slice())
    }

    Ok(launch_hash.finish())
}

#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
/// Arguments required to calculate the SEV measurement
pub struct SevMeasurementArgs<'a> {
    /// Path to OVMF file
    pub ovmf_file: PathBuf,
    /// Path to kernel file
    pub kernel_file: Option<PathBuf>,
    /// Path to initrd file
    pub initrd_file: Option<PathBuf>,
    /// Append arguments for kernel
    pub append: Option<&'a str>,
}

#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
/// Calculate an SEV launch digest
pub fn sev_calc_launch_digest(
    sev_measurement: SevMeasurementArgs,
) -> Result<[u8; 32], MeasurementError> {
    let ovmf = OVMF::new(sev_measurement.ovmf_file)?;
    let mut launch_hash = Sha256::new();
    launch_hash.update(ovmf.data().as_slice());

    if let Some(kernel) = sev_measurement.kernel_file {
        if !ovmf.is_sev_hashes_table_supported() {
            return Err(MeasurementError::InvalidOvmfKernelError);
        }
        let sev_hashes =
            SevHashes::new(kernel, sev_measurement.initrd_file, sev_measurement.append)?
                .construct_table()?;
        launch_hash.update(sev_hashes.as_slice());
    };

    Ok(launch_hash.finish())
}
