// SPDX-License-Identifier: Apache-2.0

//! Operations to handle OVMF SEV-HASHES
use openssl::sha::sha256;
use serde::Serialize;
use std::fs::File;
use std::{
    convert::{TryFrom, TryInto},
    io::Read,
    mem::size_of,
    path::PathBuf,
    str::FromStr,
};

use uuid::{uuid, Uuid};

use crate::error::*;

type Sha256Hash = [u8; 32];

/// GUID stored as little endian
#[derive(Debug, Clone, Copy, Serialize, Default)]
struct GuidLe {
    _data: [u8; 16],
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

/// SEV hash table entry
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Default)]
struct SevHashTableEntry {
    /// GUID of the SEV hash
    guid: GuidLe,
    /// Length of the hash
    length: u16,
    /// SEV HASH
    hash: Sha256Hash,
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

/// Table of SEV hashes
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Default)]
struct SevHashTable {
    /// GUID of the SEV hash table entry
    guid: GuidLe,
    /// Length of the SEV Has table entry
    length: u16,
    /// Cmd line append table entry
    cmdline: SevHashTableEntry,
    /// initrd table entry
    initrd: SevHashTableEntry,
    /// Kernel table entry
    kernel: SevHashTableEntry,
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

/// Padded SEV hash table
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Default)]
struct PaddedSevHashTable {
    ht: SevHashTable,
    padding: [u8; PaddedSevHashTable::PADDING_SIZE],
}

impl PaddedSevHashTable {
    const PADDING_SIZE: usize =
        ((size_of::<SevHashTable>() + 15) & !15) - size_of::<SevHashTable>();

    fn new(hash_table: SevHashTable) -> Self {
        PaddedSevHashTable {
            ht: hash_table,
            ..Default::default()
        }
    }
}

const SEV_HASH_TABLE_HEADER_GUID: Uuid = uuid!("9438d606-4f22-4cc9-b479-a793d411fd21");
const SEV_KERNEL_ENTRY_GUID: Uuid = uuid!("4de79437-abd2-427f-b835-d5b172d2045b");
const SEV_INITRD_ENTRY_GUID: Uuid = uuid!("44baf731-3a2f-4bd7-9af1-41e29169781d");
const SEV_CMDLINE_ENTRY_GUID: Uuid = uuid!("97d02dd8-bd20-4c94-aa78-e7714d36ab2a");

/// Struct containing the 3 possible SEV hashes
pub struct SevHashes {
    /// Kernel hash
    kernel_hash: Sha256Hash,
    /// Initrd hash
    initrd_hash: Sha256Hash,
    /// Cmdline append hash
    cmdline_hash: Sha256Hash,
}

impl SevHashes {
    /// Generate hashes from the user provided kernel, initrd, and cmdline.
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

    /// Generate the SEV hashes area - this must be *identical* to the way QEMU
    /// generates this info in order for the measurement to match.
    pub fn construct_table(&self) -> Result<Vec<u8>, MeasurementError> {
        let sev_hash_table = SevHashTable::new(
            SEV_HASH_TABLE_HEADER_GUID.to_string().as_str(),
            SevHashTableEntry::new(&SEV_CMDLINE_ENTRY_GUID, self.cmdline_hash)?,
            SevHashTableEntry::new(&SEV_INITRD_ENTRY_GUID, self.initrd_hash)?,
            SevHashTableEntry::new(&SEV_KERNEL_ENTRY_GUID, self.kernel_hash)?,
        )?;

        let padded_hash_table = PaddedSevHashTable::new(sev_hash_table);

        bincode::serialize(&padded_hash_table).map_err(|e| MeasurementError::BincodeError(*e))
    }

    /// Construct an SEV Hash page using hash table.
    pub fn construct_page(&self, offset: usize) -> Result<Vec<u8>, MeasurementError> {
        if offset >= 4096 {
            return Err(SevHashError::InvalidOffset(offset, 4096).into());
        }

        let hashes_table = self.construct_table()?;
        let mut page = Vec::with_capacity(4096);
        page.resize(offset, 0);
        page.extend_from_slice(&hashes_table[..]);
        page.resize(4096, 0);
        if page.len() != 4096 {
            return Err(SevHashError::InvalidSize(page.len(), 4096).into());
        }
        Ok(page)
    }
}
