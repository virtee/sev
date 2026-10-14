// SPDX-License-Identifier: Apache-2.0

//! Operations to handle OVMF SEV-HASHES
#[cfg(feature = "openssl")]
use openssl::sha::sha256;

#[cfg(feature = "crypto_nossl")]
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}
use std::fs::File;
use std::io::Write;
use std::{
    convert::{TryFrom, TryInto},
    io::Read,
    mem::size_of,
    path::PathBuf,
    str::FromStr,
};

use hex::FromHex;
use uuid::{uuid, Uuid};

use crate::error::*;
use crate::parser::{ByteParser, Decoder, Encoder};
use crate::util::parser_helper::{ReadExt, WriteExt};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A 32 byte-buffer intended to hold a Sha256Hash
pub type Sha256Hash = [u8; 32];

/// GUID stored as little endian
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

/// SEV hash table entry
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, Default)]
struct SevHashTableEntry {
    /// GUID of the SEV hash
    guid: GuidLe,
    /// Length of the hash
    length: u16,
    /// SEV HASH
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

/// Table of SEV hashes
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, Default)]
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

/// Padded SEV hash table
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

/// Struct containing the 3 possible SEV hashes
#[derive(Debug, Default)]
pub struct SevHashes {
    /// Kernel hash
    kernel_hash: Sha256Hash,
    /// Initrd hash
    initrd_hash: Sha256Hash,
    /// Cmdline append hash
    cmdline_hash: Sha256Hash,
}

/// Generates hash from user provided cmdline
pub fn get_cmdline_hash(append: Option<&str>) -> Sha256Hash {
    match append {
        Some(append_str) => {
            let mut append_bytes = append_str.trim().as_bytes().to_vec();
            append_bytes.extend_from_slice(b"\x00");
            sha256(&append_bytes)
        }

        None => sha256(b"\x00"),
    }
}

/// Generates hash from user provided initrd file
pub fn get_initrd_hash(initrd: Option<PathBuf>) -> Result<Sha256Hash, MeasurementError> {
    let initrd_data = match initrd {
        Some(path) => {
            let mut initrd_file = File::open(path)?;
            let mut data = Vec::new();
            initrd_file.read_to_end(&mut data)?;
            data
        }
        None => Vec::new(),
    };
    Ok(sha256(&initrd_data))
}

/// Generates hash from user provided kernel file
pub fn get_kernel_hash(kernel: PathBuf) -> Result<Sha256Hash, MeasurementError> {
    let mut kernel_file = File::open(kernel)?;
    let mut kernel_data = Vec::new();
    kernel_file.read_to_end(&mut kernel_data)?;
    Ok(sha256(&kernel_data))
}

impl<'a> TryFrom<&crate::measurement::snp::SnpMeasurementArgs<'a>> for Option<SevHashes> {
    type Error = MeasurementError;

    fn try_from(
        args: &crate::measurement::snp::SnpMeasurementArgs<'a>,
    ) -> Result<Self, MeasurementError> {
        let base = match (args.kernel_hash_str, &args.kernel_file) {
            (Some(hash), _) => {
                let hash: Sha256Hash = Vec::from_hex(hash)?
                    .try_into()
                    .map_err(|_| MeasurementError::InvalidHashLength)?;
                Some(SevHashes::default().kernel_hash(hash))
            }
            (None, Some(file)) => Some(SevHashes::default().kernel(file.clone())?),
            (None, None) => None,
        };

        base.map(|sev_hashes| -> Result<_, MeasurementError> {
            let sev_hashes = match args.initrd_hash_str {
                Some(hash) => {
                    let hash: Sha256Hash = Vec::from_hex(hash)?
                        .try_into()
                        .map_err(|_| MeasurementError::InvalidHashLength)?;
                    sev_hashes.initrd_hash(hash)
                }
                None => sev_hashes.initrd(args.initrd_file.clone())?,
            };
            Ok(sev_hashes.cmdline(args.append))
        })
        .transpose()
    }
}

impl SevHashes {
    /// Generate hashes from the user provided kernel, initrd, and cmdline.
    pub fn new(
        kernel: PathBuf,
        initrd: Option<PathBuf>,
        append: Option<&str>,
    ) -> Result<Self, MeasurementError> {
        Ok(Self::default()
            .kernel(kernel)?
            .initrd(initrd)?
            .cmdline(append)
        )
    }

    /// Sets kernel_hash to the provided value
    pub fn kernel_hash(mut self, kernel_hash: Sha256Hash) -> Self {
        self.kernel_hash = kernel_hash;
        self
    }

    /// Sets initrd_hash to the provided value
    pub fn initrd_hash(mut self, initrd_hash: Sha256Hash) -> Self {
        self.initrd_hash = initrd_hash;
        self
    }

    /// Sets cmdline_hash to the provided value
    pub fn cmdline_hash(mut self, cmdline_hash: Sha256Hash) -> Self {
        self.cmdline_hash = cmdline_hash;
        self
    }

    /// Generates hash from user provided kernel file
    pub fn kernel(mut self, kernel: PathBuf) -> Result<Self, MeasurementError> {
        self.kernel_hash = get_kernel_hash(kernel)?;
        Ok(self)
    }

    /// Generates hash from user provided initrd file
    pub fn initrd(mut self, initrd: Option<PathBuf>) -> Result<Self, MeasurementError> {
        self.initrd_hash = get_initrd_hash(initrd)?;
        Ok(self)
    }

    /// Generates hash from user provided cmdline
    pub fn cmdline(mut self, append: Option<&str>) -> Self {
        self.cmdline_hash = get_cmdline_hash(append);
        self
    }

    /// Generate the SEV hashes area - this must be *identical* to the way QEMU
    /// generates this info in order for the measurement to match.
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

    /// Construct an SEV Hash page using hash table.
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
