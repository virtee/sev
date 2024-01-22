// SPDX-License-Identifier: Apache-2.0
//! Operations to handle and create a Guest Context
use std::convert::TryInto;

use openssl::sha::sha384;

use crate::error::*;

#[cfg(target_os = "linux")]
use crate::launch::snp::PageType;

// Launch digest size in bytes
pub(crate) const LD_SIZE: usize = 384 / 8;

// VMSA page is recorded in the RMP table with GPA (u64)(-1).
// However, the address is page-aligned, and also all the bits above
// 51 are cleared.
pub(crate) const VMSA_GPA: u64 = 0xFFFFFFFFF000;

// Launch digest intialized in all zeros
const ZEROS: [u8; LD_SIZE] = [0; LD_SIZE];

fn validate_block_size(length: usize) -> Result<(), GCTXError> {
    if (length % 4096) != 0 {
        Err(GCTXError::InvalidBlockSize)
    } else {
        Ok(())
    }
}

pub(crate) struct Updating;
pub(crate) struct Completed;

/// Guest context field structure
pub struct Gctx<T> {
    /// Launch Digest, 48 bytes long
    ld: [u8; LD_SIZE],
    _state: T,
}

/// Default init of GCTX, launch digest of all 0s
impl Default for Gctx<Updating> {
    fn default() -> Self {
        Self {
            ld: ZEROS,
            _state: Updating,
        }
    }
}

impl Gctx<Updating> {
    /// Initialize a new guest context using existing data
    pub fn new(seed: &[u8]) -> Result<Self, MeasurementError> {
        Ok(Self {
            ld: seed.try_into()?,
            _state: Updating,
        })
    }

    /// Will update guest context launch digest with provided data from page
    fn update(&mut self, page_type: u8, gpa: u64, contents: &[u8]) -> Result<(), GCTXError> {
        let page_info_len: u16 = 0x70;
        let is_imi: u8 = 0;
        let vmpl3_perms: u8 = 0;
        let vmpl2_perms: u8 = 0;
        let vmpl1_perms: u8 = 0;

        let mut page_info: Vec<u8> = self.ld.to_vec();
        page_info.extend_from_slice(contents);

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

    /// Update Lanunch digest type accprding to page type and guest physical address.
    /// Some Page types don't require data. Some page types just require size of the page.
    #[cfg(target_os = "linux")]
    pub fn update_page(
        &mut self,
        page_type: PageType,
        gpa: u64,
        contents: Option<&[u8]>,
        length_bytes: Option<usize>,
    ) -> Result<(), GCTXError> {
        match page_type {
            PageType::Normal => {
                if let Some(data) = contents {
                    validate_block_size(data.len())?;
                    let mut offset = 0;
                    while offset < data.len() {
                        let page_data = &data[offset..offset + 4096];
                        self.update(
                            page_type as u8,
                            gpa + offset as u64,
                            sha384(page_data).as_slice(),
                        )?;
                        offset += 4096;
                    }
                    Ok(())
                } else {
                    Err(GCTXError::MissingData)
                }
            }

            PageType::Vmsa => {
                if let Some(data) = contents {
                    validate_block_size(data.len())?;
                    self.update(page_type as u8, VMSA_GPA, sha384(data).as_slice())?;
                    Ok(())
                } else {
                    Err(GCTXError::MissingData)
                }
            }

            PageType::Zero => {
                if let Some(length_bytes) = length_bytes {
                    validate_block_size(length_bytes)?;
                    let mut offset = 0;
                    while offset < length_bytes {
                        self.update(page_type as u8, gpa + offset as u64, &ZEROS)?;
                        offset += 4096;
                    }
                    Ok(())
                } else {
                    Err(GCTXError::MissingBlockSize)
                }
            }

            PageType::Unmeasured => {
                self.update(page_type as u8, gpa, &ZEROS)?;
                Ok(())
            }

            PageType::Secrets => {
                self.update(page_type as u8, gpa, &ZEROS)?;
                Ok(())
            }

            PageType::Cpuid => {
                self.update(page_type as u8, gpa, &ZEROS)?;
                Ok(())
            }
        }
    }

    /// Update is done and now we switch to a completed state
    pub(crate) fn finished(&self) -> Gctx<Completed> {
        Gctx {
            ld: self.ld,
            _state: Completed,
        }
    }
}

impl Gctx<Completed> {
    /// Get the launch digest bytes
    pub(crate) fn ld(&self) -> &[u8; LD_SIZE] {
        &self.ld
    }
}
