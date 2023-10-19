// SPDX-License-Identifier: Apache-2.0

use openssl::sha::sha384;

use crate::error::*;
use std::convert::TryInto;

// Launch digest size in bytes
const LD_SIZE: usize = 384 / 8;

// VMSA page is recorded in the RMP table with GPA (u64)(-1).
// However, the address is page-aligned, and also all the bits above
// 51 are cleared.
const VMSA_GPA: u64 = 0xFFFFFFFFF000;

// Launch digest intialized in all zeros
const ZEROS: [u8; LD_SIZE] = [0; LD_SIZE];

/// Guest context field structure
pub struct Gctx {
    /// Launch Digest, 48 bytes long
    ld: [u8; LD_SIZE],
}

/// Default init of GCTX, launch digest of all 0s
impl Default for Gctx {
    fn default() -> Gctx {
        Gctx { ld: ZEROS }
    }
}

impl Gctx {
    /// Initialize a new guest context using existing data
    pub fn new(seed: &[u8]) -> Result<Self, MeasurementError> {
        Ok(Self {
            ld: seed.try_into()?,
        })
    }

    /// Get the launch digest bytes
    pub fn get_ld(self) -> [u8; LD_SIZE] {
        self.ld
    }

    /// Will update guest context launch digest with provided data from page
    fn update(
        &mut self,
        page_type: u8,
        gpa: u64,
        contents: [u8; LD_SIZE],
    ) -> Result<(), GCTXError> {
        let page_info_len: u16 = 0x70;
        let is_imi: u8 = 0;
        let vmpl3_perms: u8 = 0;
        let vmpl2_perms: u8 = 0;
        let vmpl1_perms: u8 = 0;

        let mut page_info: Vec<u8> = self.ld.to_vec();
        page_info.extend_from_slice(&contents);

        page_info.extend_from_slice(&page_info_len.to_le_bytes());
        page_info.extend_from_slice(&page_type.to_le_bytes());
        page_info.extend_from_slice(&is_imi.to_le_bytes());

        page_info.extend_from_slice(&vmpl3_perms.to_le_bytes());
        page_info.extend_from_slice(&vmpl2_perms.to_le_bytes());
        page_info.extend_from_slice(&vmpl1_perms.to_le_bytes());
        page_info.extend_from_slice(&(0_u8).to_le_bytes());

        page_info.extend_from_slice(&gpa.to_le_bytes());

        if page_info.len() != (page_info_len as usize) {
            return Err(GCTXError::InvalidPageSize(
                page_info.len(),
                page_info_len as usize,
            ));
        }

        self.ld = sha384(&page_info);

        Ok(())
    }

    /// Update launch digest using normal memory pages
    pub fn update_normal_pages(&mut self, start_gpa: u64, data: &[u8]) -> Result<(), GCTXError> {
        if (data.len() % 4096) != 0 {
            return Err(GCTXError::InvalidBlockSize);
        }
        let mut offset = 0;
        while offset < data.len() {
            let page_data = &data[offset..offset + 4096];
            self.update(0x01, start_gpa + offset as u64, sha384(page_data))?;
            offset += 4096;
        }
        Ok(())
    }

    /// Update launch digest using VMSA memory pages
    pub fn update_vmsa_page(&mut self, data: &[u8]) -> Result<(), GCTXError> {
        if data.len() != 4096 {
            return Err(GCTXError::InvalidBlockSize);
        }
        self.update(0x02, VMSA_GPA, sha384(data))?;
        Ok(())
    }

    /// Update launch digest using ZERO pages
    pub fn update_zero_pages(&mut self, gpa: u64, length_bytes: usize) -> Result<(), GCTXError> {
        if (length_bytes % 4096) != 0 {
            return Err(GCTXError::InvalidBlockSize);
        };
        let mut offset = 0;
        while offset < length_bytes {
            self.update(0x03, gpa + offset as u64, ZEROS)?;
            offset += 4096;
        }
        Ok(())
    }

    /// Update launch digest using an unmeasured page
    fn _update_unmeasured_page(&mut self, gpa: u64) -> Result<(), GCTXError> {
        self.update(0x04, gpa, ZEROS)?;
        Ok(())
    }

    /// Update launch digest using a secret page
    pub fn update_secrets_page(&mut self, gpa: u64) -> Result<(), GCTXError> {
        self.update(0x05, gpa, ZEROS)?;
        Ok(())
    }

    /// Update launch digest using a CPUID page
    pub fn update_cpuid_page(&mut self, gpa: u64) -> Result<(), GCTXError> {
        self.update(0x06, gpa, ZEROS)?;
        Ok(())
    }
}
