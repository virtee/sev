// SPDX-License-Identifier: Apache-2.0

//! SNP certificate table entry types.
//!
//! [`CertTableEntry`] is the portable representation of one certificate in an
//! SNP certificate chain (a [`CertType`] GUID plus DER bytes). Entries are
//! ordered by `cert_type` when building endorsement chains.
//!
//! On Linux, [`CertTableEntry::cert_table_to_vec_bytes`] and
//! [`CertTableEntry::vec_bytes_to_cert_table`] convert between these values and
//! the kernel `sev-guest` wire layout implemented by
//! [`KernelCertTableEntry`](crate::firmware::guest::cert_table::KernelCertTableEntry)
//! in `firmware::guest::cert_table`.

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    types::snp::CertType,
    util::parser_helper::{ReadExt, WriteExt},
};
use std::{
    convert::TryInto,
    io::{Read, Write},
};

#[cfg(all(target_os = "linux", feature = "attester"))]
use crate::{error::CertError, firmware::guest::cert_table::KernelCertTableEntry};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Certificate payload referenced by pointer or owned bytes.
///
/// Used where ioctl buffers accept either a userspace pointer or an inline
/// vector depending on the caller context.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RawData {
    /// A mutable pointer to an unsigned byte.
    Pointer(*mut u8),
    /// A vector of bytes.
    Vector(Vec<u8>),
}

impl From<*mut u8> for RawData {
    fn from(value: *mut u8) -> Self {
        Self::Pointer(value)
    }
}

impl<const SIZE: usize> From<[u8; SIZE]> for RawData {
    fn from(value: [u8; SIZE]) -> Self {
        Self::Vector(value.into())
    }
}

impl From<&mut [u8]> for RawData {
    fn from(value: &mut [u8]) -> Self {
        Self::Vector(value.into())
    }
}

impl From<Vec<u8>> for RawData {
    fn from(value: Vec<u8>) -> Self {
        Self::Vector(value)
    }
}

impl From<&Vec<u8>> for RawData {
    fn from(value: &Vec<u8>) -> Self {
        Self::Vector(value.to_vec())
    }
}

impl From<&mut Vec<u8>> for RawData {
    fn from(value: &mut Vec<u8>) -> Self {
        Self::Vector(value.to_vec())
    }
}

/// One certificate in an SNP certificate table.
///
/// Each entry pairs a well-known [`CertType`] GUID (ARK, ASK, VCEK, VLEK, …)
/// with the raw certificate DER. Use [`CertTableEntry::new`] or
/// [`CertTableEntry::from_guid`] to construct entries for endorser chain
/// building.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CertTableEntry {
    /// Certificate type GUID.
    pub cert_type: CertType,
    /// The raw data of the certificate.
    pub data: Vec<u8>,
}

impl Encoder<()> for CertTableEntry {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.cert_type.clone(), ())?;
        writer.write_bytes(self.data.clone(), ())?;
        Ok(())
    }
}

impl Decoder<()> for CertTableEntry {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let cert_type = reader.read_bytes()?;
        let data = reader.read_bytes()?;
        Ok(Self { cert_type, data })
    }
}

impl ByteParser<()> for CertTableEntry {
    type Bytes = Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        let mut rdr: &[u8] = bytes;
        Self::decode(&mut rdr, ())
    }

    fn to_bytes(&self) -> std::io::Result<Self::Bytes> {
        let mut out = Vec::new();
        self.encode(&mut out, ())?;
        Ok(out)
    }
}

impl CertTableEntry {
    /// Returns the certificate type GUID as a string.
    pub fn guid_string(&self) -> String {
        self.cert_type.to_string()
    }

    /// Returns the raw certificate bytes.
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Creates an entry from a UUID and certificate bytes.
    pub fn from_guid(guid: &uuid::Uuid, data: Vec<u8>) -> Result<Self, uuid::Error> {
        Ok(Self {
            cert_type: guid.try_into()?,
            data,
        })
    }

    /// Creates an entry from a certificate type and raw bytes.
    pub fn new(cert_type: CertType, data: Vec<u8>) -> Self {
        Self { cert_type, data }
    }

    /// Builds a kernel-formatted certificate table for the PSP.
    ///
    /// Accepts Rust-friendly [`CertTableEntry`] values and returns the
    /// contiguous buffer expected by the Linux `sev-guest` driver, including the
    /// zero-GUID terminator and trailing certificate payloads.
    #[cfg(all(target_os = "linux", feature = "attester"))]
    pub fn cert_table_to_vec_bytes(table: &[Self]) -> Result<Vec<u8>, CertError> {
        KernelCertTableEntry::uapi_to_vec_bytes(table)
    }

    /// Parses a kernel certificate-table buffer into [`CertTableEntry`] values.
    ///
    /// The input must be a buffer in the layout produced by
    /// [`Self::cert_table_to_vec_bytes`] or populated by the kernel for an
    /// extended attestation report.
    #[cfg(all(target_os = "linux", feature = "attester"))]
    pub fn vec_bytes_to_cert_table(bytes: &mut [u8]) -> Result<Vec<Self>, CertError> {
        let cert_bytes_ptr: *mut KernelCertTableEntry =
            bytes.as_mut_ptr() as *mut KernelCertTableEntry;

        unsafe { KernelCertTableEntry::parse_table(cert_bytes_ptr) }
            .map_err(|_| CertError::InvalidGUID)
    }
}

impl Ord for CertTableEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cert_type.cmp(&other.cert_type)
    }
}

impl PartialOrd for CertTableEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::{CertTableEntry, RawData};
    use crate::types::snp::CertType;
    use uuid::Uuid;

    mod raw_data {
        use super::RawData;

        #[test]
        fn from_array() {
            let expected = RawData::Vector(vec![1; 72]);
            let actual: RawData = [1; 72].into();
            assert_eq!(expected, actual);
        }
    }

    mod cert_table_entry {
        use super::*;
        use crate::parser::ByteParser;

        #[test]
        fn creation() {
            let data = vec![1, 2, 3, 4];
            let entry = CertTableEntry::new(CertType::ARK, data.clone());

            assert_eq!(entry.cert_type, CertType::ARK);
            assert_eq!(entry.data(), &data);
            assert_eq!(entry.guid_string(), "c0b406a4-a803-4952-9743-3fb6014cd0ae");
        }

        #[test]
        fn from_guid() {
            let guid = Uuid::parse_str("c0b406a4-a803-4952-9743-3fb6014cd0ae").unwrap();
            let data = vec![1, 2, 3, 4];
            let entry = CertTableEntry::from_guid(&guid, data.clone()).unwrap();

            assert_eq!(entry.cert_type, CertType::ARK);
            assert_eq!(entry.data(), &data);
        }

        #[test]
        fn invalid_guid() {
            let guid = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
            let data = vec![1, 2, 3, 4];
            let entry = CertTableEntry::from_guid(&guid, data.clone()).unwrap();

            assert!(matches!(entry.cert_type, CertType::OTHER(_)));
        }

        #[test]
        fn empty() {
            let entry = CertTableEntry::new(CertType::Empty, vec![]);

            assert_eq!(entry.cert_type, CertType::Empty);
            assert!(entry.data().is_empty());
            assert_eq!(entry.guid_string(), "00000000-0000-0000-0000-000000000000");
        }

        #[test]
        fn ordering() {
            let entry1 = CertTableEntry::new(CertType::ARK, vec![1]);
            let entry2 = CertTableEntry::new(CertType::ASK, vec![2]);
            let entry3 = CertTableEntry::new(CertType::Empty, vec![3]);

            assert!(entry1 < entry2);
            assert!(entry2 < entry3);
            assert!(entry1 < entry3);
        }

        #[test]
        fn data_access() {
            let large_data = vec![0u8; 1024];
            let entry = CertTableEntry::new(CertType::VCEK, large_data.clone());

            assert_eq!(entry.data(), &large_data);
        }

        #[test]
        fn deserialization() {
            let entry = CertTableEntry::new(CertType::ARK, vec![1, 2, 3, 4]);

            let serialized = entry.to_bytes().unwrap();
            let deserialized = CertTableEntry::from_bytes(&serialized).unwrap();

            assert_eq!(entry.cert_type, deserialized.cert_type);
            assert_eq!(entry.data, deserialized.data);
        }

        #[test]
        fn cmp_complete() {
            let entries = vec![
                CertTableEntry::new(CertType::ARK, vec![1]),
                CertTableEntry::new(CertType::VCEK, vec![2]),
                CertTableEntry::new(CertType::Empty, vec![4]),
                CertTableEntry::new(CertType::ASK, vec![3]),
            ];

            let mut sorted = entries.clone();
            sorted.sort();

            assert_eq!(sorted[0].cert_type, CertType::ARK);
            assert_eq!(sorted[1].cert_type, CertType::VCEK);
            assert_eq!(sorted[2].cert_type, CertType::ASK);
            assert_eq!(sorted[3].cert_type, CertType::Empty);
        }

        #[test]
        fn complete_ordering() {
            let entries = vec![
                CertTableEntry::new(CertType::ARK, vec![1, 2, 3]),
                CertTableEntry::new(CertType::ARK, vec![9, 9, 9]),
                CertTableEntry::new(CertType::VCEK, vec![1]),
                CertTableEntry::new(CertType::ASK, vec![2]),
                CertTableEntry::new(CertType::CRL, vec![3]),
                CertTableEntry::new(CertType::Empty, vec![]),
                CertTableEntry::new(
                    CertType::OTHER(
                        Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                    ),
                    vec![4],
                ),
                CertTableEntry::new(
                    CertType::OTHER(
                        Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
                    ),
                    vec![5],
                ),
            ];

            assert_eq!(entries[0], entries[0]);
            assert!(entries[0] < entries[2]);
            assert!(entries[2] < entries[3]);
            assert!(entries[3] < entries[4]);
            assert!(entries[4] < entries[6]);
            assert!(entries[6] < entries[7]);
            assert!(entries[6] < entries[5]);
            assert!(entries[0] < entries[3]);
            assert!(entries[0] < entries[5]);
            assert!(entries[5] > entries[0]);
            assert!(entries[4] > entries[3]);
        }

        #[test]
        fn sort_and_compare() {
            let mut entries = vec![
                CertTableEntry::new(CertType::Empty, vec![]),
                CertTableEntry::new(CertType::CRL, vec![1]),
                CertTableEntry::new(
                    CertType::OTHER(
                        Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
                    ),
                    vec![2],
                ),
                CertTableEntry::new(
                    CertType::OTHER(
                        Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                    ),
                    vec![3],
                ),
                CertTableEntry::new(CertType::ARK, vec![4]),
                CertTableEntry::new(CertType::ASK, vec![5]),
                CertTableEntry::new(CertType::VCEK, vec![6]),
                CertTableEntry::new(CertType::VLEK, vec![7]),
            ];

            let expected = vec![
                CertTableEntry::new(CertType::ARK, vec![4]),
                CertTableEntry::new(CertType::VCEK, vec![6]),
                CertTableEntry::new(CertType::VLEK, vec![7]),
                CertTableEntry::new(CertType::ASK, vec![5]),
                CertTableEntry::new(CertType::CRL, vec![1]),
                CertTableEntry::new(
                    CertType::OTHER(
                        Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                    ),
                    vec![3],
                ),
                CertTableEntry::new(
                    CertType::OTHER(
                        Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
                    ),
                    vec![2],
                ),
                CertTableEntry::new(CertType::Empty, vec![]),
            ];

            entries.sort();
            assert_eq!(entries, expected);

            let mut duplicates = [
                CertTableEntry::new(CertType::ARK, vec![1]),
                CertTableEntry::new(CertType::ARK, vec![2]),
            ];
            duplicates.sort();
            assert_eq!(duplicates[0].data(), &[1]);
            assert_eq!(duplicates[1].data(), &[2]);
        }

        #[test]
        fn direct_cmp() {
            let entry1 = CertTableEntry::new(CertType::ARK, vec![1]);
            let entry2 = CertTableEntry::new(CertType::VCEK, vec![2]);

            assert!(matches!(entry1.cmp(&entry2), std::cmp::Ordering::Less));
            assert!(matches!(entry2.cmp(&entry1), std::cmp::Ordering::Greater));
            assert!(matches!(entry1.cmp(&entry1), std::cmp::Ordering::Equal));
        }

        #[test]
        fn direct_cmp_vlek() {
            let entry1 = CertTableEntry::new(CertType::ARK, vec![1]);
            let entry2 = CertTableEntry::new(CertType::VLEK, vec![2]);

            assert!(matches!(entry1.cmp(&entry2), std::cmp::Ordering::Less));
            assert!(matches!(entry2.cmp(&entry1), std::cmp::Ordering::Greater));
            assert!(matches!(entry1.cmp(&entry1), std::cmp::Ordering::Equal));
        }

        #[test]
        fn deserialize_roundtrip() {
            let original = CertTableEntry::new(CertType::ARK, vec![0x41, 0x42, 0x43]);

            let serialized = original.to_bytes().unwrap();
            let deserialized = CertTableEntry::from_bytes(&serialized).unwrap();

            assert_eq!(deserialized.cert_type, original.cert_type);
            assert_eq!(deserialized.data(), original.data());
        }
    }

    #[cfg(all(target_os = "linux", feature = "attester"))]
    mod kernel_wire {
        use super::*;

        fn build_vec_uapi_cert_table() -> Vec<CertTableEntry> {
            vec![
                CertTableEntry::new(CertType::ARK, vec![1; 25]),
                CertTableEntry::new(CertType::ASK, vec![2; 25]),
                CertTableEntry::new(CertType::VCEK, vec![5; 15]),
                CertTableEntry::new(
                    CertType::OTHER(
                        Uuid::parse_str("fbb6ed74-e73e-44ab-8893-4252792d737a").unwrap(),
                    ),
                    vec![7; 6],
                ),
            ]
        }

        #[test]
        fn cert_table_to_vec_bytes() {
            let data = build_vec_uapi_cert_table();
            let actual = CertTableEntry::cert_table_to_vec_bytes(&data).unwrap();
            assert!(!actual.is_empty());
        }

        #[test]
        fn roundtrip() {
            let entries = vec![
                CertTableEntry::new(CertType::ARK, vec![1, 2, 3]),
                CertTableEntry::new(CertType::ASK, vec![4, 5, 6]),
            ];

            let mut bytes = CertTableEntry::cert_table_to_vec_bytes(&entries).unwrap();
            let converted = CertTableEntry::vec_bytes_to_cert_table(&mut bytes).unwrap();

            assert_eq!(entries.len(), converted.len());
            assert_eq!(entries[0].cert_type, converted[0].cert_type);
            assert_eq!(entries[1].cert_type, converted[1].cert_type);
        }

        #[test]
        fn conversion() {
            let entries = vec![
                CertTableEntry::new(CertType::ARK, vec![1, 2, 3]),
                CertTableEntry::new(CertType::ASK, vec![4, 5, 6]),
            ];

            let mut bytes = CertTableEntry::cert_table_to_vec_bytes(&entries).unwrap();
            let converted = CertTableEntry::vec_bytes_to_cert_table(&mut bytes).unwrap();

            assert_eq!(entries.len(), converted.len());
            assert_eq!(entries[0].cert_type, converted[0].cert_type);
            assert_eq!(entries[1].cert_type, converted[1].cert_type);
        }

        #[test]
        fn chain_visitor_methods() {
            let chain_data = vec![
                CertTableEntry::new(CertType::ARK, vec![1]),
                CertTableEntry::new(CertType::ASK, vec![2]),
            ];
            let mut serialized = CertTableEntry::cert_table_to_vec_bytes(&chain_data).unwrap();
            let deserialized = CertTableEntry::vec_bytes_to_cert_table(&mut serialized).unwrap();

            assert_eq!(deserialized.len(), chain_data.len());
            assert_eq!(deserialized[0].cert_type, chain_data[0].cert_type);
        }
    }
}
