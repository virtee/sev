// SPDX-License-Identifier: Apache-2.0

//! Operations to handle ovmf data
use crate::error::*;
use crate::parser::{ByteParser, Decoder, Encoder};
use crate::util::parser_helper::{ReadExt, WriteExt};
use byteorder::{ByteOrder, LittleEndian};
use std::io::Write;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fs::File,
    io::{Cursor, Read},
    path::PathBuf,
};
use super::snp::SnpLaunchDigest;
use uuid::{uuid, Uuid};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Convert a UUID into a little endian slice
pub fn guid_le_to_slice(guid: &str) -> Result<[u8; 16], MeasurementError> {
    let guid = Uuid::try_from(guid)?;
    let guid = guid.to_bytes_le();
    let guid = guid.as_slice();

    Ok(guid.try_into()?)
}

/// Types of sections declared by OVMF SEV Metadata, as appears in: https://github.com/tianocore/edk2/blob/edk2-stable202405/OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SectionType {
    /// SNP Secure Memory
    SnpSecMemory = 1,
    /// SNP secret
    SnpSecrets = 2,
    /// CPUID
    Cpuid = 3,
    /// SVSM_CAA
    SvsmCaa = 4,
    /// SNP kernel hashes
    SnpKernelHashes = 0x10,
}

impl Default for SectionType {
    fn default() -> Self {
        Self::SnpSecMemory
    }
}

impl Encoder<()> for SectionType {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        let value: u8 = match self {
            SectionType::SnpSecMemory => 1,
            SectionType::SnpSecrets => 2,
            SectionType::Cpuid => 3,
            SectionType::SvsmCaa => 4,
            SectionType::SnpKernelHashes => 0x10,
        };
        writer.write_bytes(value.to_le_bytes(), ())?;
        Ok(())
    }
}

impl Decoder<()> for SectionType {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let value = u8::from_le_bytes(reader.read_bytes()?);
        match value {
            1 => Ok(SectionType::SnpSecMemory),
            2 => Ok(SectionType::SnpSecrets),
            3 => Ok(SectionType::Cpuid),
            4 => Ok(SectionType::SvsmCaa),
            0x10 => Ok(SectionType::SnpKernelHashes),
            _ => Err(std::io::ErrorKind::Unsupported.into()),
        }
    }
}

impl ByteParser<()> for SectionType {
    type Bytes = [u8; 1];
    const EXPECTED_LEN: Option<usize> = Some(1);
}

impl TryFrom<u8> for SectionType {
    type Error = OVMFError;

    fn try_from(value: u8) -> Result<Self, OVMFError> {
        match value {
            1 => Ok(SectionType::SnpSecMemory),
            2 => Ok(SectionType::SnpSecrets),
            3 => Ok(SectionType::Cpuid),
            4 => Ok(SectionType::SvsmCaa),
            0x10 => Ok(SectionType::SnpKernelHashes),
            _ => Err(OVMFError::InvalidSectionType),
        }
    }
}

/// OVMF SEV Metadata Section Description
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct OvmfSevMetadataSectionDesc {
    /// Guest Physical Adress
    pub gpa: u32,
    /// Size
    pub size: u32,
    /// Section Type
    pub section_type: SectionType,
}

impl Encoder<()> for OvmfSevMetadataSectionDesc {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.gpa, ())?;
        writer.write_bytes(self.size, ())?;
        writer.write_bytes(self.section_type, ())?;
        Ok(())
    }
}

impl Decoder<()> for OvmfSevMetadataSectionDesc {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let gpa = reader.read_bytes()?;
        let size = reader.read_bytes()?;
        let section_type = reader.read_bytes()?;
        Ok(Self {
            gpa,
            size,
            section_type,
        })
    }
}

impl ByteParser<()> for OvmfSevMetadataSectionDesc {
    // packed representation: 4 (gpa) + 4 (size) + 1 (section_type) = 9 bytes
    type Bytes = [u8; 9];
    const EXPECTED_LEN: Option<usize> = Some(9);
}

impl OvmfSevMetadataSectionDesc {
    fn bytes_from_offset(value: &[u8], offset: usize) -> Result<Self, std::io::Error> {
        let mut bytes = &value[offset..offset + std::mem::size_of::<OvmfSevMetadataSectionDesc>()];
        let decoded = Self::decode(&mut bytes, ())?;

        Ok(decoded)
    }
}

/// OVMF Metadata Header
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[derive(Debug, Clone, Copy)]
struct OvmfSevMetadataHeader {
    /// Header Signature
    signature: [u8; 4],
    /// Size
    size: u32,
    /// Version
    version: u32,
    /// Number of items
    num_items: u32,
}

impl Encoder<()> for OvmfSevMetadataHeader {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.signature, ())?;
        writer.write_bytes(self.size, ())?;
        writer.write_bytes(self.version, ())?;
        writer.write_bytes(self.num_items, ())?;
        Ok(())
    }
}

impl Decoder<()> for OvmfSevMetadataHeader {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let signature = reader.read_bytes()?;
        let size = reader.read_bytes()?;
        let version = reader.read_bytes()?;
        let num_items = reader.read_bytes()?;
        Ok(Self {
            signature,
            size,
            version,
            num_items,
        })
    }
}

impl ByteParser<()> for OvmfSevMetadataHeader {
    // packed representation: 4 (signature) + 4 (size) + 4 (version) + 4 (num_items) = 16 bytes
    type Bytes = [u8; 16];
    const EXPECTED_LEN: Option<usize> = Some(16);
}

impl OvmfSevMetadataHeader {
    fn bytes_from_offset(value: &[u8], offset: usize) -> Result<Self, std::io::Error> {
        let mut bytes = &value[offset..offset + std::mem::size_of::<OvmfSevMetadataHeader>()];
        let decoded = Self::decode(&mut bytes, ())?;

        Ok(decoded)
    }

    /// Verify Header Signature
    fn verify(&self) -> Result<(), OVMFError> {
        let expected_signature: &[u8] = b"ASEV";
        if !self.signature.eq(expected_signature) {
            return Err(OVMFError::SEVMetadataVerification("signature".to_string()));
        }

        if self.version != 1 {
            return Err(OVMFError::SEVMetadataVerification("version".to_string()));
        }

        Ok(())
    }
}

/// OVMF Footer
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct OvmfFooterTableEntry {
    /// Size
    size: u16,
    /// GUID
    guid: [u8; 16],
}

impl TryFrom<&[u8]> for OvmfFooterTableEntry {
    type Error = MeasurementError;

    /// Generate footer from data
    fn try_from(value: &[u8]) -> Result<OvmfFooterTableEntry, MeasurementError> {
        // Bytes 2-17 are the GUID
        let guid: [u8; 16] = value[2..18].try_into()?;
        // first 2 bytes are the size
        let size_nums: [u8; 2] = value[0..2].try_into()?;
        let size = u16::from_le_bytes(size_nums);
        Ok(OvmfFooterTableEntry { size, guid })
    }
}

const FOUR_GB: u64 = 0x100000000;
const OVMF_TABLE_FOOTER_GUID: Uuid = uuid!("96b582de-1fb2-45f7-baea-a366c55a082d");
const SEV_HASH_TABLE_RV_GUID: Uuid = uuid!("7255371f-3a3b-4b04-927b-1da6efa8d454");
const SEV_ES_RESET_BLOCK_GUID: Uuid = uuid!("00f771de-1a7e-4fcb-890e-68c77e2fb44e");
const OVMF_SEV_META_DATA_GUID: Uuid = uuid!("dc886566-984a-4798-a75e-5585a7bf67cc");

/// Compact binary representation of an OVMF's parsed metadata,
/// excluding the raw firmware data.
///
/// Pairs the serialized `table` and `metadata_items` with an
/// [`SnpLaunchDigest`] of the original firmware image, which is
/// sufficient to resume a launch measurement without the full OVMF file.
pub struct OvmfBlob {
    /// Serialized table and metadata items.
    pub bytes: Vec<u8>,
    /// Launch digest of the OVMF firmware data.
    pub digest: Option<SnpLaunchDigest>,
}

#[cfg(feature = "serde")]
impl Serialize for OvmfBlob {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let raw = self.to_bytes().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&STANDARD.encode(raw))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for OvmfBlob {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let s = String::deserialize(deserializer)?;
        let raw = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        OvmfBlob::try_from(raw.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// OVMF Structure
pub struct OVMF {
    /// OVMF data
    data: Vec<u8>,
    /// Table matching GUID to its data
    table: HashMap<Uuid, Vec<u8>>,
    /// Metadata item description
    metadata_items: Vec<OvmfSevMetadataSectionDesc>,
}

impl OVMF {
    /// Generate new OVMF structure by parsing the footer table and SEV metadata
    pub fn new(ovmf_file: PathBuf) -> Result<Self, MeasurementError> {
        let mut data = Vec::new();
        let mut file = match File::open(ovmf_file) {
            Ok(file) => file,
            Err(e) => return Err(MeasurementError::FileError(e)),
        };

        file.read_to_end(&mut data)?;

        let mut ovmf = OVMF {
            data,
            table: HashMap::new(),
            metadata_items: Vec::new(),
        };

        ovmf.parse_footer_table()?;
        ovmf.parse_sev_metadata()?;

        Ok(ovmf)
    }

    /// Grab OVMF data
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Calculate OVMF GPA
    pub fn gpa(&self) -> u64 {
        FOUR_GB - self.data.len() as u64
    }

    /// Get an item from the OVMF table
    fn table_item(&self, guid: &Uuid) -> Option<&Vec<u8>> {
        self.table.get(guid)
    }

    /// Get the OVMF metadata items
    pub fn metadata_items(&self) -> &Vec<OvmfSevMetadataSectionDesc> {
        &self.metadata_items
    }

    /// Check if the metadata items have the desired section
    pub fn has_metadata_section(&self, section_type: SectionType) -> bool {
        self.metadata_items()
            .iter()
            .any(|s| s.section_type == section_type)
    }

    /// Check that the table supports SEV hashes
    pub fn is_sev_hashes_table_supported(&self) -> bool {
        self.table.contains_key(&SEV_HASH_TABLE_RV_GUID)
            && self.sev_hashes_table_gpa().unwrap_or(0) != 0
    }

    /// Get the SEV HASHES GPA
    pub fn sev_hashes_table_gpa(&self) -> Result<u64, OVMFError> {
        if !self.table.contains_key(&SEV_HASH_TABLE_RV_GUID) {
            return Err(OVMFError::EntryMissingInTable(
                "SEV_HASH_TABLE_RV_GUID".to_string(),
            ));
        }

        if let Some(gpa) = self
            .table_item(&SEV_HASH_TABLE_RV_GUID)
            .and_then(|entry| entry.get(..4))
            .map(|bytes| LittleEndian::read_u32(bytes) as u64)
        {
            Ok(gpa)
        } else {
            Err(OVMFError::GetTableItemError)
        }
    }

    /// Get the SEV-ES EIP
    pub fn sev_es_reset_eip(&self) -> Result<u32, OVMFError> {
        if !self.table.contains_key(&SEV_ES_RESET_BLOCK_GUID) {
            return Err(OVMFError::EntryMissingInTable(
                "SEV_ES_RESET_BLOCK_GUID".to_string(),
            ));
        }

        if let Some(eip) = self
            .table_item(&SEV_ES_RESET_BLOCK_GUID)
            .and_then(|entry| entry.get(..4))
            .map(LittleEndian::read_u32)
        {
            Ok(eip)
        } else {
            Err(OVMFError::GetTableItemError)
        }
    }

    /// Parse footer table data
    fn parse_footer_table(&mut self) -> Result<(), MeasurementError> {
        self.table.clear();
        let size = self.data.len();
        const ENTRY_HEADER_SIZE: usize = std::mem::size_of::<OvmfFooterTableEntry>();
        //The OVMF table ends 32 bytes before the end of the firmware binary
        let start_of_footer_table = size - 32 - ENTRY_HEADER_SIZE;
        let footer =
            OvmfFooterTableEntry::try_from(&self.data.as_slice()[start_of_footer_table..])?;

        let expected_footer_guid = guid_le_to_slice(OVMF_TABLE_FOOTER_GUID.to_string().as_str())?;

        if !footer.guid.eq(&expected_footer_guid) {
            return Err(OVMFError::MismatchingGUID)?;
        }

        if (footer.size as usize) < ENTRY_HEADER_SIZE {
            return Err(OVMFError::InvalidSize(
                "OVMF Table Footer".to_string(),
                footer.size as usize,
                ENTRY_HEADER_SIZE,
            ))?;
        }

        let table_size = footer.size as usize - ENTRY_HEADER_SIZE;

        let table_start = start_of_footer_table - table_size;
        let table_bytes = &self.data[table_start..start_of_footer_table];
        let mut offset = table_size;
        while offset >= ENTRY_HEADER_SIZE {
            let entry =
                OvmfFooterTableEntry::try_from(&table_bytes[offset - ENTRY_HEADER_SIZE..offset])?;
            if entry.size < ENTRY_HEADER_SIZE as u16 {
                return Err(OVMFError::InvalidSize(
                    "OVMF Table Entry".to_string(),
                    entry.size as usize,
                    ENTRY_HEADER_SIZE,
                ))?;
            }
            let entry_guid = Uuid::from_slice_le(&entry.guid)?;

            if offset < entry.size as usize {
                break;
            }
            let entry_data = &table_bytes[offset - entry.size as usize..offset - ENTRY_HEADER_SIZE];
            self.table.insert(entry_guid, entry_data.to_vec());

            offset -= entry.size as usize;
        }

        Ok(())
    }

    /// parse SEV metadata
    fn parse_sev_metadata(&mut self) -> Result<(), MeasurementError> {
        match self.table.get(&OVMF_SEV_META_DATA_GUID) {
            Some(entry) => {
                let offset_from_end = i32::from_le_bytes(entry[..4].try_into()?);
                let header_start = self.data.len() - (offset_from_end as usize);
                let header =
                    OvmfSevMetadataHeader::bytes_from_offset(self.data.as_slice(), header_start)?;
                header.verify()?;
                let items = &self.data[header_start + std::mem::size_of::<OvmfSevMetadataHeader>()
                    ..header_start + header.size as usize];
                for i in 0..header.num_items {
                    let offset = (i as usize) * std::mem::size_of::<OvmfSevMetadataSectionDesc>();
                    let item = OvmfSevMetadataSectionDesc::bytes_from_offset(items, offset)?;
                    self.metadata_items.push(item.to_owned());
                }
            }

            None => {
                return Err(OVMFError::EntryMissingInTable(
                    "OVMF_SEV_METADATA_GUID".to_string(),
                ))?;
            }
        }

        Ok(())
    }
}

impl OvmfBlob {
    /// Create an `OvmfBlob` from a parsed [`OVMF`] and an optional launch
    /// digest computed from its firmware data.
    pub fn new(ovmf: &OVMF, digest: Option<SnpLaunchDigest>) -> Result<Self, MeasurementError> {
        let mut buf = Vec::new();

        let num_entries = ovmf.table.len() as u32;
        buf.write_bytes(num_entries, ())?;
        for (uuid, data) in &ovmf.table {
            buf.write_all(uuid.as_bytes())?;
            let data_len = data.len() as u32;
            buf.write_bytes(data_len, ())?;
            buf.write_all(data)?;
        }

        let num_items = ovmf.metadata_items.len() as u32;
        buf.write_bytes(num_items, ())?;
        for item in &ovmf.metadata_items {
            buf.write_bytes(*item, ())?;
        }

        Ok(OvmfBlob { bytes: buf, digest })
    }

    /// Serialize the entire `OvmfBlob` into a single binary buffer.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MeasurementError> {
        let mut buf = Vec::new();
        match &self.digest {
            Some(digest) => {
                buf.write_bytes(1u8, ())?;
                buf.write_bytes(*digest, ())?;
            }
            None => {
                buf.write_bytes(0u8, ())?;
            }
        }
        let bytes_len = self.bytes.len() as u32;
        buf.write_bytes(bytes_len, ())?;
        buf.write_all(&self.bytes)?;
        Ok(buf)
    }
}

impl TryFrom<&[u8]> for OvmfBlob {
    type Error = MeasurementError;

    fn try_from(data: &[u8]) -> Result<Self, MeasurementError> {
        let mut cursor = Cursor::new(data);
        let has_digest: u8 = cursor.read_bytes()?;
        let digest = if has_digest != 0 {
            Some(cursor.read_bytes()?)
        } else {
            None
        };
        let bytes_len: u32 = cursor.read_bytes()?;
        let mut bytes = vec![0u8; bytes_len as usize];
        cursor.read_exact(&mut bytes)?;
        Ok(OvmfBlob { bytes, digest })
    }
}

impl TryFrom<OvmfBlob> for OVMF {
    type Error = MeasurementError;

    fn try_from(blob: OvmfBlob) -> Result<Self, MeasurementError> {
        let mut cursor = Cursor::new(&blob.bytes);

        let num_entries: u32 = cursor.read_bytes()?;
        let mut table = HashMap::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            let mut uuid_bytes = [0u8; 16];
            cursor.read_exact(&mut uuid_bytes)?;
            let uuid = Uuid::from_bytes(uuid_bytes);
            let data_len: u32 = cursor.read_bytes()?;
            let mut data = vec![0u8; data_len as usize];
            cursor.read_exact(&mut data)?;
            table.insert(uuid, data);
        }

        let num_items: u32 = cursor.read_bytes()?;
        let mut metadata_items = Vec::with_capacity(num_items as usize);
        for _ in 0..num_items {
            let item: OvmfSevMetadataSectionDesc = cursor.read_bytes()?;
            metadata_items.push(item);
        }

        Ok(Self {
            data: Vec::new(),
            table,
            metadata_items,
        })
    }
}
