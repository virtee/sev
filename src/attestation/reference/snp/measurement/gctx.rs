// SPDX-License-Identifier: Apache-2.0

//! Guest context (GCTX) launch digest state machine.
//!
//! Implements the SNP firmware launch digest update algorithm used to compute
//! the **expected measurement** (see [module terminology](super)). Each
//! measured guest page folds into a running 48-byte SHA-384 value via a
//! fixed 0x70-byte *page info* structure:
//!
//! ```text
//!  page_info = current_ld || page_digest || metadata || gpa
//!  next_ld   = SHA-384(page_info)
//! ```
//!
//! [`Gctx`] tracks that running value. Public callers use
//! [`super::calc_snp_ovmf_hash`] and [`super::snp_calc_launch_digest`]; this
//! module is the shared engine both paths use.
//!
//! # State machine
//!
//! ```text
//!  Gctx<Updating>::default()  or  Gctx::new(seed)
//!           │
//!           │  update_page(...)  (repeat per firmware page)
//!           ▼
//!  Gctx<Updating>
//!           │
//!           │  finished()
//!           ▼
//!  Gctx<Completed>::ld()  ──►  SnpLaunchDigest
//! ```
//!
//! The `Updating` / `Completed` marker types prevent reading the launch digest
//! before all pages have been applied.

use std::convert::TryInto;

use crate::{
    attestation::reference::digest::sha384,
    error::*,
    types::snp::PageType,
    types::snp::{SnpLaunchDigest, LD_BYTES},
};

/// Guest physical address recorded for VMSA pages in the RMP table.
///
/// Firmware uses page-aligned GPA `0xFFFFFFFFF000` (bits above 51 cleared).
/// [`Gctx::update_page`] always uses this GPA for [`PageType::Vmsa`] regardless
/// of the `gpa` argument.
pub(crate) const VMSA_GPA: u64 = 0xFFFFFFFFF000;

/// Placeholder digest for page types that measure fixed zero content.
const ZEROS: [u8; LD_BYTES] = [0; LD_BYTES];

/// Require 4 KiB-aligned spans for multi-page normal/zero updates.
fn validate_block_size(length: usize) -> Result<(), GCTXError> {
    if (length % 4096) != 0 {
        Err(GCTXError::InvalidBlockSize)
    } else {
        Ok(())
    }
}

/// GCTX is accepting page updates.
pub(crate) struct Updating;

/// GCTX updates are complete; the launch digest may be read.
pub(crate) struct Completed;

/// SNP guest context launch digest accumulator.
///
/// Generic over [`Updating`] (mutable measurement in progress) or
/// [`Completed`] (final expected measurement available via [`Gctx::ld`]).
///
/// # Usage
///
/// 1. [`Gctx::default`] — start from an all-zero launch digest.
/// 2. [`Gctx::new`] — start from an existing digest (OVMF pre-hash).
/// 3. [`Gctx::update_page`] — apply each firmware-equivalent page.
/// 4. [`Gctx::finished`] — freeze state and read [`SnpLaunchDigest`].
pub struct Gctx<T> {
    /// Running launch digest / expected measurement (48 bytes).
    ld: SnpLaunchDigest,
    _state: T,
}

impl Default for Gctx<Updating> {
    /// Create a guest context whose launch digest is initially all zeros.
    fn default() -> Self {
        Self {
            ld: SnpLaunchDigest::default(),
            _state: Updating,
        }
    }
}

impl Gctx<Updating> {
    /// Initialize a guest context from an existing 48-byte launch digest seed.
    ///
    /// Used when the OVMF portion was pre-computed (via [`super::calc_snp_ovmf_hash`])
    /// and subsequent updates should start from that partial expected measurement.
    ///
    /// # Arguments
    ///
    /// * `seed` — exactly [`LD_BYTES`] (48) bytes of hex-decoded launch digest.
    ///
    /// # Errors
    ///
    /// Returns [`MeasurementError`](crate::error::MeasurementError) when `seed`
    /// is not exactly 48 bytes.
    pub fn new(seed: &[u8]) -> Result<Self, MeasurementError> {
        Ok(Self {
            ld: seed.try_into()?,
            _state: Updating,
        })
    }

    /// Fold one page into the running launch digest using the firmware page-info layout.
    ///
    /// `contents` is either a 48-byte page digest (normal/VMSA pages) or the
    /// zero placeholder for secrets/CPUID/unmeasured pages.
    fn update(&mut self, page_type: u8, gpa: u64, contents: &[u8]) -> Result<(), MeasurementError> {
        let page_info_len: u16 = 0x70;
        let is_imi: u8 = 0;
        let vmpl3_perms: u8 = 0;
        let vmpl2_perms: u8 = 0;
        let vmpl1_perms: u8 = 0;

        let mut page_info: Vec<u8> = self.ld.try_into()?;
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
            ))?;
        }
        self.ld = sha384(&page_info).as_slice().try_into()?;

        Ok(())
    }

    /// Update the launch digest for one firmware page at `gpa`.
    ///
    /// Each call advances the running **expected measurement** by one or more
    /// 4 KiB pages, matching SNP launch measurement rules.
    ///
    /// # Page types
    ///
    /// | [`PageType`] | `contents` | `length_bytes` | Behavior |
    /// |--------------|------------|----------------|----------|
    /// | `Normal` | raw page bytes | — | SHA-384 each 4 KiB sub-page at `gpa + offset` |
    /// | `Vmsa` | VMSA struct bytes | — | SHA-384 once at [`VMSA_GPA`] |
    /// | `Zero` | — | total span | Zero digest per 4 KiB page from `gpa` |
    /// | `Secrets` | ignored | — | Zero digest at `gpa` |
    /// | `Cpuid` | ignored | — | Zero digest at `gpa` |
    /// | `Unmeasured` | ignored | — | Zero digest at `gpa` |
    ///
    /// # Errors
    ///
    /// * [`GCTXError::MissingData`](crate::error::GCTXError::MissingData) — `Normal`/`Vmsa` without `contents`
    /// * [`GCTXError::MissingBlockSize`](crate::error::GCTXError::MissingBlockSize) — `Zero` without `length_bytes`
    /// * [`GCTXError::InvalidBlockSize`](crate::error::GCTXError::InvalidBlockSize) — length not 4 KiB-aligned
    /// * [`GCTXError::InvalidPageSize`](crate::error::GCTXError::InvalidPageSize) — internal page-info layout error
    pub fn update_page(
        &mut self,
        page_type: PageType,
        gpa: u64,
        contents: Option<&[u8]>,
        length_bytes: Option<usize>,
    ) -> Result<(), MeasurementError> {
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
                    Err(GCTXError::MissingData)?
                }
            }

            PageType::Vmsa => {
                if let Some(data) = contents {
                    validate_block_size(data.len())?;
                    self.update(page_type as u8, VMSA_GPA, sha384(data).as_slice())?;
                    Ok(())
                } else {
                    Err(GCTXError::MissingData)?
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
                    Err(GCTXError::MissingBlockSize)?
                }
            }

            PageType::Unmeasured | PageType::Secrets | PageType::Cpuid => {
                self.update(page_type as u8, gpa, &ZEROS)?;
                Ok(())
            }
        }
    }

    /// Finalize page updates and return an immutable context.
    ///
    /// After this call the launch digest cannot be modified; read it with
    /// [`Gctx::ld`] on the returned [`Gctx<Completed>`].
    pub(crate) fn finished(&self) -> Gctx<Completed> {
        Gctx {
            ld: self.ld,
            _state: Completed,
        }
    }
}

impl Gctx<Completed> {
    /// Return the computed launch digest (expected measurement).
    pub(crate) fn ld(&self) -> SnpLaunchDigest {
        self.ld
    }
}
