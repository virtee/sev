// SPDX-License-Identifier: Apache-2.0

//! OVMF SEV-HASHES table construction for launch measurement.
//!
//! Builds the **SEV-HASHES** blob that OVMF/QEMU embeds in guest firmware memory.
//! During SNP or SEV launch digest calculation, this table is measured as a
//! normal 4 KiB page so changes to the kernel, initrd, or kernel command line
//! change the guest **expected measurement**.
//!
//! # Role in measurement
//!
//! ```text
//!  kernel file ──► SHA-256 ──┐
//!  initrd file ──► SHA-256 ──┼──► SevHashTable ──► 4 KiB page ──► GCTX update
//!  cmdline     ──► SHA-256 ──┘         ▲
//!                                       │
//!                              SevHashes::construct_page()
//! ```
//!
//! [`SevHashes::construct_page`] layout must match QEMU's generator byte-for-byte
//! or the computed launch digest will not match firmware.
//!
//! Used by:
//!
//! * [`crate::attestation::reference::snp::measurement::snp_calc_launch_digest`]
//! * [`crate::attestation::reference::sev::sev_calc_launch_digest`] and related SEV measurement APIs
//!
//! # Public API
//!
//! | Method | Purpose |
//! |--------|---------|
//! | [`SevHashes::new`] | Hash kernel, optional initrd, optional cmdline |
//! | [`SevHashes::construct_table`] | Serialized 168-byte (+ padding) hash table |
//! | [`SevHashes::construct_page`] | Full 4 KiB guest page at a GPA offset |
//!
//! Wire layout types (`SevHashTable`, entries, GUIDs) are private; only
//! [`SevHashes`] is public.

use crate::attestation::reference::digest::sha256;
use std::fs::File;
use std::io::Write;
use std::{
    convert::{TryFrom, TryInto},
    io::Read,
    mem::size_of,
    path::PathBuf,
    str::FromStr,
};

use uuid::{uuid, Uuid};

use crate::error::*;
use crate::parser::{ByteParser, Decoder, Encoder};
use crate::util::parser_helper::{ReadExt, WriteExt};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

type Sha256Hash = [u8; 32];

/// GUID stored as little endian (OVMF wire format).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, Default)]
struct GuidLe {
    _data: [u8; 16],
}

impl Encoder<()> for GuidLe {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self._data, ())?;
        Ok(())
    }
}

impl Decoder<()> for GuidLe {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let data = reader.read_bytes()?;
        Ok(Self { _data: data })
    }
}

impl ByteParser<()> for GuidLe {
    type Bytes = [u8; 16];
    const EXPECTED_LEN: Option<usize> = Some(16);
}

impl TryFrom<&Uuid> for GuidLe {
    type Error = MeasurementError;

    fn try_from(value: &Uuid) -> Result<Self, Self::Error> {
        let guid = value.to_bytes_le();
        let guid = guid.as_slice();
        Ok(Self {
            _data: guid.try_into()?,
        })
    }
}

impl FromStr for GuidLe {
    type Err = MeasurementError;

    fn from_str(guid: &str) -> Result<Self, MeasurementError> {
        let guid = Uuid::try_from(guid)?;
        let guid = guid.to_bytes_le();
        let guid = guid.as_slice();
        Ok(Self {
            _data: guid.try_into()?,
        })
    }
}

/// One entry in the OVMF SEV-HASHES table (cmdline, initrd, or kernel).
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, Default)]
struct SevHashTableEntry {
    guid: GuidLe,
    length: u16,
    hash: Sha256Hash,
}

impl Encoder<()> for SevHashTableEntry {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.guid, ())?;
        writer.write_bytes(self.length, ())?;
        writer.write_bytes(self.hash, ())?;
        Ok(())
    }
}

impl Decoder<()> for SevHashTableEntry {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let guid = reader.read_bytes()?;
        let length = reader.read_bytes()?;
        let hash = reader.read_bytes()?;
        Ok(Self { guid, length, hash })
    }
}

impl ByteParser<()> for SevHashTableEntry {
    type Bytes = [u8; 50];
    const EXPECTED_LEN: Option<usize> = Some(50);
}

impl SevHashTableEntry {
    fn new(guid: &Uuid, hash: Sha256Hash) -> Result<Self, MeasurementError> {
        Ok(Self {
            guid: GuidLe::try_from(guid)?,
            length: std::mem::size_of::<SevHashTableEntry>() as u16,
            hash,
        })
    }
}

/// OVMF SEV-HASHES table header plus cmdline, initrd, and kernel entries.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, Default)]
struct SevHashTable {
    guid: GuidLe,
    length: u16,
    cmdline: SevHashTableEntry,
    initrd: SevHashTableEntry,
    kernel: SevHashTableEntry,
}

impl Encoder<()> for SevHashTable {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.guid, ())?;
        writer.write_bytes(self.length, ())?;
        writer.write_bytes(self.cmdline, ())?;
        writer.write_bytes(self.initrd, ())?;
        writer.write_bytes(self.kernel, ())?;
        Ok(())
    }
}

impl Decoder<()> for SevHashTable {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let guid = reader.read_bytes()?;
        let length = reader.read_bytes()?;
        let cmdline = reader.read_bytes()?;
        let initrd = reader.read_bytes()?;
        let kernel = reader.read_bytes()?;
        Ok(Self {
            guid,
            length,
            cmdline,
            initrd,
            kernel,
        })
    }
}

impl ByteParser<()> for SevHashTable {
    type Bytes = [u8; 168];
    const EXPECTED_LEN: Option<usize> = Some(168);
}

impl SevHashTable {
    fn new(
        guid: &str,
        cmdline: SevHashTableEntry,
        initrd: SevHashTableEntry,
        kernel: SevHashTableEntry,
    ) -> Result<Self, MeasurementError> {
        Ok(Self {
            guid: GuidLe::from_str(guid)?,
            length: std::mem::size_of::<SevHashTable>() as u16,
            cmdline,
            initrd,
            kernel,
        })
    }
}

/// SEV-HASHES table with 16-byte alignment padding (QEMU layout).
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, Default)]
struct PaddedSevHashTable {
    ht: SevHashTable,
    padding: [u8; PaddedSevHashTable::PADDING_SIZE],
}

impl Encoder<()> for PaddedSevHashTable {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.ht, ())?;
        writer.write_bytes(self.padding, ())?;
        Ok(())
    }
}

impl Decoder<()> for PaddedSevHashTable {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let ht = reader.read_bytes()?;
        let padding = reader.read_bytes()?;
        Ok(Self { ht, padding })
    }
}

impl ByteParser<()> for PaddedSevHashTable {
    type Bytes = [u8; 168 + PaddedSevHashTable::PADDING_SIZE];
    const EXPECTED_LEN: Option<usize> = Some(168 + PaddedSevHashTable::PADDING_SIZE);
}

impl PaddedSevHashTable {
    const PADDING_SIZE: usize =
        ((size_of::<SevHashTable>() + 15) & !15) - size_of::<SevHashTable>();

    fn new(hash_table: SevHashTable) -> Self {
        PaddedSevHashTable {
            ht: hash_table,
            padding: [0; Self::PADDING_SIZE],
        }
    }
}

const SEV_HASH_TABLE_HEADER_GUID: Uuid = uuid!("9438d606-4f22-4cc9-b479-a793d411fd21");
const SEV_KERNEL_ENTRY_GUID: Uuid = uuid!("4de79437-abd2-427f-b835-d5b172d2045b");
const SEV_INITRD_ENTRY_GUID: Uuid = uuid!("44baf731-3a2f-4bd7-9af1-41e29169781d");
const SEV_CMDLINE_ENTRY_GUID: Uuid = uuid!("97d02dd8-bd20-4c94-aa78-e7714d36ab2a");

/// SHA-256 hashes of the guest kernel, initrd, and kernel command line.
///
/// Input to OVMF **SEV-HASHES** page construction during launch digest
/// calculation. Hashing rules match QEMU:
///
/// * **Kernel** — SHA-256 of the entire kernel file.
/// * **Initrd** — SHA-256 of the initrd file, or SHA-256 of empty bytes when absent.
/// * **Cmdline** — SHA-256 of trimmed append string + NUL, or SHA-256 of a single NUL when absent.
pub struct SevHashes {
    kernel_hash: Sha256Hash,
    initrd_hash: Sha256Hash,
    cmdline_hash: Sha256Hash,
}

impl SevHashes {
    /// Build hashes from guest boot artifacts on disk.
    ///
    /// # Arguments
    ///
    /// * `kernel` — path to the guest kernel image (required).
    /// * `initrd` — optional path to the initrd/initramfs image.
    /// * `append` — optional kernel command-line append string (whitespace trimmed;
    ///   a trailing NUL is included in the hash).
    ///
    /// # Errors
    ///
    /// [`MeasurementError`](crate::error::MeasurementError) on file I/O failure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sev::attestation::reference::sev_hashes::SevHashes;
    /// use std::path::PathBuf;
    ///
    /// let hashes = SevHashes::new(
    ///     PathBuf::from("vmlinuz"),
    ///     Some(PathBuf::from("initrd.img")),
    ///     Some("console=ttyS0"),
    /// )?;
    /// ```
    pub fn new(
        kernel: PathBuf,
        initrd: Option<PathBuf>,
        append: Option<&str>,
    ) -> Result<Self, MeasurementError> {
        let mut kernel_file = File::open(kernel)?;
        let mut kernel_data = Vec::new();
        kernel_file.read_to_end(&mut kernel_data)?;

        let kernel_hash = sha256(&kernel_data);
        let initrd_data = match initrd {
            Some(path) => {
                let mut initrd_file = File::open(path)?;
                let mut data = Vec::new();
                initrd_file.read_to_end(&mut data)?;
                data
            }
            None => Vec::new(),
        };

        let initrd_hash = sha256(&initrd_data);

        let cmdline_hash = match append {
            Some(append_str) => {
                let mut append_bytes = append_str.trim().as_bytes().to_vec();
                append_bytes.extend_from_slice(b"\x00");
                sha256(&append_bytes)
            }

            None => sha256(b"\x00"),
        };

        Ok(SevHashes {
            kernel_hash,
            initrd_hash,
            cmdline_hash,
        })
    }

    /// Serialize the OVMF SEV-HASHES table (168 bytes + alignment padding).
    ///
    /// Output must be **identical** to QEMU's table for the same inputs or the
    /// launch digest will not match firmware.
    ///
    /// # Returns
    ///
    /// Padded table bytes (`168 + padding`); use [`Self::construct_page`] for the
    /// full 4 KiB guest page.
    ///
    /// # Errors
    ///
    /// Propagates wire-encoding errors as [`MeasurementError`](crate::error::MeasurementError).
    pub fn construct_table(
        &self,
    ) -> Result<[u8; 168 + PaddedSevHashTable::PADDING_SIZE], MeasurementError> {
        let sev_hash_table = SevHashTable::new(
            SEV_HASH_TABLE_HEADER_GUID.to_string().as_str(),
            SevHashTableEntry::new(&SEV_CMDLINE_ENTRY_GUID, self.cmdline_hash)?,
            SevHashTableEntry::new(&SEV_INITRD_ENTRY_GUID, self.initrd_hash)?,
            SevHashTableEntry::new(&SEV_KERNEL_ENTRY_GUID, self.kernel_hash)?,
        )?;

        let padded_hash_table = PaddedSevHashTable::new(sev_hash_table);

        let bytes = padded_hash_table.to_bytes()?;

        Ok(bytes)
    }

    /// Build the 4 KiB guest page containing the SEV-HASHES table.
    ///
    /// Places the padded hash table at `offset` within a zero-filled 4096-byte
    /// page. The offset comes from the OVMF metadata GPA
    /// ([`OVMF::sev_hashes_table_gpa`](crate::types::shared::reference::ovmf::OVMF::sev_hashes_table_gpa))
    /// and is used when measuring the `SNP_KERNEL_HASHES` section.
    ///
    /// # Arguments
    ///
    /// * `offset` — byte offset within the page (must be `< 4096`).
    ///
    /// # Returns
    ///
    /// Exactly 4096 bytes suitable for a [`PageType::Normal`] GCTX update.
    ///
    /// # Errors
    ///
    /// * [`SevHashError::InvalidOffset`](crate::error::SevHashError::InvalidOffset) — `offset >= 4096`
    /// * [`SevHashError::InvalidSize`](crate::error::SevHashError::InvalidSize) — internal layout error
    pub fn construct_page(&self, offset: usize) -> Result<Vec<u8>, MeasurementError> {
        if offset >= 4096 {
            return Err(SevHashError::InvalidOffset(offset, 4096))?;
        }

        let hashes_table = self.construct_table()?;
        let mut page = Vec::with_capacity(4096);
        page.resize(offset, 0);
        page.extend_from_slice(&hashes_table[..]);
        page.resize(4096, 0);
        if page.len() != 4096 {
            return Err(SevHashError::InvalidSize(page.len(), 4096))?;
        }
        Ok(page)
    }
}
