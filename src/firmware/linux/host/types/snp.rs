// SPDX-License-Identifier: Apache-2.0

use std::ops::{Deref, DerefMut};

#[cfg(target_os = "linux")]
use crate::error::CertError;

use crate::{error::HashstickError, firmware::host as UAPI};

#[cfg(target_os = "linux")]
use uuid::Uuid;

/// Raw certificate bytes (by pointer or Vec<u8>).
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

/// Structure used for interacting with the Linux Kernel.
///
/// The original C structure looks like this:
///
/// ```C
/// struct cert_table {
///    struct {
///       unsigned char guid[16];
///       uint32 offset;
///       uint32 length;
///    } cert_table_entry[];
/// };
/// ```
///
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct CertTableEntry {
    /// Sixteen character GUID.
    guid: [u8; 16],

    /// The starting location of the certificate blob.
    offset: u32,

    /// The number of bytes to read from the offset.
    length: u32,
}

impl CertTableEntry {
    /// Builds a Kernel formatted CertTable for sending the certificate content to the PSP.
    ///
    /// Users should pass the rust-friendly vector of [UAPI::CertTableEntry](crate::firmware::host::types::snp::CertTableEntry), and this function
    /// will handle adding the last entry and the structuring of the buffer sent to the hypervisor.
    ///
    /// The contiguous memory layout should look similar to this:
    ///
    /// ```text
    ///             |-> |------------------|    |-  CertTableEntry -|
    ///             |   | CertTableEntry_1 <<<--| - guid            |
    ///             |   | CertTableEntry_2 |    | - offset          |
    /// CertTable --|   | ...              |    | - length          |
    ///             |   | ...              |    |-------------------|
    ///             |   | ...              |
    ///             |-> | CertTableEntry_z | <-- last entry all zeroes
    /// offset (1)  --> | RawCertificate_1 |
    ///                 | ...              |
    ///                 | ...              |
    /// offset (2)  --> | RawCertificate_2 |
    ///                 | ...              |
    ///                 | ...              |
    /// offset (n)  --> | RawCertificate_n |
    ///                 |------------------|
    ///
    /// ```
    ///
    #[cfg(target_os = "linux")]
    pub fn uapi_to_vec_bytes(table: &[UAPI::CertTableEntry]) -> Result<Vec<u8>, CertError> {
        // Create the vector to return for later.
        let mut bytes: Vec<u8> = vec![];

        // Find the location where the first certificate should begin.
        let mut offset: u32 = (std::mem::size_of::<CertTableEntry>() * (table.len() + 1)) as u32;

        // Create the buffer to store the table and certificates.
        let mut raw_certificates: Vec<u8> = vec![];

        for entry in table.iter() {
            let guid: Uuid = match Uuid::parse_str(&entry.guid_string()) {
                Ok(uuid) => uuid,
                Err(_) => return Err(CertError::InvalidGUID),
            };

            // Append the guid to the byte array.
            bytes.extend_from_slice(guid.as_bytes());

            // Append the offset location to the byte array.
            bytes.extend_from_slice(&offset.to_ne_bytes());

            // Append the length to the byte array.
            bytes.extend_from_slice(&(entry.data.len() as u32).to_ne_bytes());

            // Copy the certificate data out until concatenating it later.
            raw_certificates.extend_from_slice(entry.data.as_slice());

            // Increment the offset
            offset += entry.data.len() as u32;
        }

        // Append the the empty entry to signify the end of the table.
        bytes.append(&mut vec![0u8; 24]);

        // Append the certificate bytes to the end of the table.
        bytes.append(&mut raw_certificates);

        Ok(bytes)
    }

    /// Parses the raw array of bytes into more human understandable information.
    ///
    /// The original C structure looks like this:
    ///
    /// ```C
    /// struct cert_table {
    ///    struct {
    ///       unsigned char guid[16];
    ///       uint32 offset;
    ///       uint32 length;
    ///    } cert_table_entry[];
    /// };
    /// ```
    ///
    #[cfg(target_os = "linux")]
    pub unsafe fn parse_table(
        mut data: *mut CertTableEntry,
    ) -> Result<Vec<UAPI::CertTableEntry>, uuid::Error> {
        // Helpful Constance for parsing the data
        const ZERO_GUID: Uuid = Uuid::from_bytes([0x0; 16]);

        // Pre-defined re-usable variables.
        let table_ptr: *mut u8 = data as *mut u8;

        // Create a location to store the final data.
        let mut retval: Vec<UAPI::CertTableEntry> = vec![];

        // Start parsing the PSP data from the pointers.
        let mut entry: CertTableEntry;

        loop {
            // Dereference the pointer to parse the table data.
            entry = *data;
            let guid: Uuid = Uuid::from_slice(entry.guid.as_slice())?;

            // Once we find a zeroed GUID, we are done.
            if guid == ZERO_GUID {
                break;
            }

            // Calculate the beginning and ending pointers of the raw certificate data.
            let mut cert_bytes: Vec<u8> = vec![];
            let mut cert_addr: *mut u8 = table_ptr.offset(entry.offset as isize);
            let cert_end: *mut u8 = cert_addr.add(entry.length as usize);

            // Gather the certificate bytes.
            while cert_addr != cert_end {
                cert_bytes.push(*cert_addr);
                cert_addr = cert_addr.add(1usize);
            }

            // Build the Rust-friendly structure and append vector to be returned when
            // we are finished.
            retval.push(UAPI::CertTableEntry::from_guid(&guid, cert_bytes.clone())?);

            // Move the pointer ahead to the next value.
            data = data.offset(1isize);
        }

        Ok(retval)
    }
}

/// SNP_COMMIT structure  
/// - length: length of the command buffer read by the PSP  
#[cfg(feature = "snp")]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct SnpCommit {
    pub buffer: u32,
}

/// Sets the system wide configuration values for SNP.
#[cfg(feature = "snp")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SnpSetConfig {
    /// The TCB_VERSION to report in guest attestation reports.
    pub reported_tcb: UAPI::TcbVersion,

    /// mask_id [0] : whether chip id is present in attestation reports or not  
    /// mask_id [1]: whether attestation reports are signed or not
    /// rsvd [2:31]: reserved
    pub mask_id: UAPI::MaskId,

    /// Reserved. Must be zero.
    reserved: [u8; 52],
}

impl Default for SnpSetConfig {
    fn default() -> Self {
        Self {
            reported_tcb: Default::default(),
            mask_id: Default::default(),
            reserved: [0; 52],
        }
    }
}

// Length defined in the Linux Kernel for the IOCTL.
const HASHSTICK_BUFFER_LEN: usize = 432;

#[cfg(feature = "snp")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
/// Wrapped VLEK data.
pub struct WrappedVlekHashstick<'a> {
    /// Wrapped VLEK data provided by AMD Key Distribution Server as bytes.
    /// Address to this data is passed to the AMD Secure Processor.
    pub data: &'a [u8], // 432 bytes of data
}

impl<'a, 'b: 'a> std::convert::TryFrom<&'b [u8]> for WrappedVlekHashstick<'a> {
    type Error = HashstickError;

    fn try_from(value: &'b [u8]) -> Result<Self, Self::Error> {
        if value.len() != HASHSTICK_BUFFER_LEN {
            return Err(HashstickError::InvalidLength);
        }

        if value == [0u8; HASHSTICK_BUFFER_LEN] {
            return Err(HashstickError::EmptyHashstickBuffer);
        }

        // Validate reserved fields are zero as required by spec
        // Check first reserved field (0x0C-0x0F)
        if value[0x0C..0x10] != [0u8; 4] {
            return Err(HashstickError::InvalidReservedField);
        }

        // Check second reserved field (0x198-0x19F)
        if value[0x198..0x1A0] != [0u8; 8] {
            return Err(HashstickError::InvalidReservedField);
        }

        Ok(Self { data: value })
    }
}

#[cfg(feature = "snp")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
/// Structure used to load a VLEK hashstick into the AMD Secure Processor.
pub struct SnpVlekLoad {
    /// Length of the command buffer read by the AMD Secure Processor.
    pub len: u32,

    /// Version of wrapped VLEK hashstick (Must be 0h).
    pub vlek_wrapped_version: u8,

    _reserved: [u8; 3],

    /// Address of wrapped VLEK hashstick ([WrappedVlekHashstick])
    pub vlek_wrapped_address: u64,
}

#[cfg(feature = "snp")]
impl SnpVlekLoad {
    /// Creates a new VLEK load instruction from a hashstick.
    pub fn new(hashstick: &WrappedVlekHashstick) -> Self {
        hashstick.into()
    }
}

impl<'a> std::convert::From<&WrappedVlekHashstick<'a>> for SnpVlekLoad {
    fn from(value: &WrappedVlekHashstick<'a>) -> Self {
        Self {
            len: value.data.len() as u32,
            vlek_wrapped_version: 0u8,
            _reserved: Default::default(),
            vlek_wrapped_address: value as *const WrappedVlekHashstick as u64,
        }
    }
}

#[cfg(feature = "snp")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
/// Kernel-friendly Snp Platform Status
pub struct SnpPlatformStatus {
    pub buffer: [u8; 32],
}

impl Deref for SnpPlatformStatus {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for SnpPlatformStatus {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl AsRef<[u8]> for SnpPlatformStatus {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

impl AsMut<[u8]> for SnpPlatformStatus {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

#[cfg(test)]
mod test {
    use crate::firmware::host::FFI::types::SnpSetConfig;

    #[test]
    fn test_snp_set_config_default() {
        let expected: SnpSetConfig = SnpSetConfig {
            reported_tcb: Default::default(),
            mask_id: Default::default(),
            reserved: [0; 52],
        };
        let actual: SnpSetConfig = Default::default();
        assert_eq!(expected, actual);
    }

    mod raw_data {

        use crate::firmware::linux::host::types::RawData;

        #[test]
        fn test_from_array() {
            let expected: RawData = RawData::Vector(vec![1; 72]);

            let actual: RawData = [1; 72].into();

            assert_eq!(expected, actual);
        }

        #[test]
        fn test_from_u8_slice() {
            let mut value: [u8; 20] = [2; 20];
            let value_slice: &mut [u8] = &mut value;
            let expected: RawData = RawData::Vector(vec![2; 20]);
            let actual: RawData = value_slice.into();
            assert_eq!(expected, actual);
        }

        #[test]
        fn test_from_u8_ptr() {
            let mut value: [u8; 20] = [2; 20];
            let value_ref: *mut u8 = value.as_mut_ptr();
            let expected: RawData = RawData::Pointer(value_ref);
            let actual: RawData = value_ref.into();
            assert_eq!(expected, actual);
        }

        #[test]
        fn test_from_u8_vec() {
            let value: Vec<u8> = vec![2; 20];
            let expected: RawData = RawData::Vector(vec![2; 20]);
            let actual: RawData = value.into();
            assert_eq!(expected, actual);
        }

        #[test]
        fn test_from_u8_vec_ref() {
            let value: Vec<u8> = vec![2; 20];
            let actual: RawData = (&value).into();
            let expected: RawData = RawData::Vector(value);
            assert_eq!(expected, actual);
        }

        #[test]
        fn test_from_u8_vec_mut_ref() {
            let mut value: Vec<u8> = vec![2; 20];
            let actual: RawData = (&mut value).into();
            let expected: RawData = RawData::Vector(value);
            assert_eq!(expected, actual);
        }
    }

    #[cfg(target_os = "linux")]
    mod hashstick {
        use std::convert::TryFrom;

        use crate::{error::HashstickError, firmware::linux::host::types::SnpVlekLoad};

        use super::super::{WrappedVlekHashstick, HASHSTICK_BUFFER_LEN};

        const VALID_HASHSTICK_BYTES: [u8; HASHSTICK_BUFFER_LEN] = [
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];

        const INVALID_HASHSTICK_BYTES: [u8; 25] = [2u8; 25];

        #[test]
        fn test_bytes_to_wrapped_hashstick() {
            let bytes: [u8; HASHSTICK_BUFFER_LEN] = VALID_HASHSTICK_BYTES;
            let expected: WrappedVlekHashstick = WrappedVlekHashstick { data: &bytes };
            let actual: WrappedVlekHashstick =
                WrappedVlekHashstick::try_from(VALID_HASHSTICK_BYTES.as_slice()).unwrap();

            assert_eq!(actual, expected)
        }

        #[test]
        fn test_invalid_bytes_to_wrapped_hashstick() {
            assert_eq!(
                WrappedVlekHashstick::try_from(INVALID_HASHSTICK_BYTES.as_slice()).unwrap_err(),
                HashstickError::InvalidLength
            );
        }

        #[test]
        fn test_empty_buffer_to_wrapped_hashstick() {
            assert_eq!(
                WrappedVlekHashstick::try_from([0; HASHSTICK_BUFFER_LEN].as_slice()).unwrap_err(),
                HashstickError::EmptyHashstickBuffer
            )
        }

        #[test]
        fn test_wrapped_hashtick_into_snp_vlek_load() {
            let test_hashstick: WrappedVlekHashstick =
                WrappedVlekHashstick::try_from(VALID_HASHSTICK_BYTES.as_slice()).unwrap();

            let actual: SnpVlekLoad = (&test_hashstick).into();

            let expected: SnpVlekLoad = SnpVlekLoad {
                len: HASHSTICK_BUFFER_LEN as u32,
                vlek_wrapped_version: 0u8,
                _reserved: Default::default(),
                vlek_wrapped_address: &test_hashstick as *const WrappedVlekHashstick as u64,
            };

            assert_eq!(actual, expected);
        }

        #[test]
        fn test_snp_vlek_load_new() {
            let test_hashstick: WrappedVlekHashstick =
                WrappedVlekHashstick::try_from(VALID_HASHSTICK_BYTES.as_slice()).unwrap();

            let actual: SnpVlekLoad = SnpVlekLoad::new(&test_hashstick);

            let expected: SnpVlekLoad = SnpVlekLoad {
                len: HASHSTICK_BUFFER_LEN as u32,
                vlek_wrapped_version: 0u8,
                _reserved: Default::default(),
                vlek_wrapped_address: &test_hashstick as *const WrappedVlekHashstick as u64,
            };

            assert_eq!(actual, expected);
        }
    }

    #[cfg(target_os = "linux")]
    mod cert_table_entry {

        use crate::firmware::host as UAPI;
        use crate::firmware::linux::host::types::CertTableEntry;
        use uuid::Uuid;

        fn build_vec_uapi_cert_table() -> Vec<UAPI::CertTableEntry> {
            vec![
                UAPI::CertTableEntry::new(UAPI::CertType::ARK, vec![1; 25]),
                UAPI::CertTableEntry::new(UAPI::CertType::ASK, vec![2; 25]),
                UAPI::CertTableEntry::new(UAPI::CertType::VCEK, vec![5; 15]),
                UAPI::CertTableEntry::new(
                    UAPI::CertType::OTHER(
                        Uuid::parse_str("fbb6ed74-e73e-44ab-8893-4252792d737a").unwrap(),
                    ),
                    vec![7; 6],
                ),
            ]
        }

        #[test]
        fn test_uapi_to_vec_bytes() {
            let expected: Vec<u8> = vec![
                192, 180, 6, 164, 168, 3, 73, 82, 151, 67, 63, 182, 1, 76, 208, 174, 120, 0, 0, 0,
                25, 0, 0, 0, 74, 183, 179, 121, 187, 172, 79, 228, 160, 47, 5, 174, 243, 39, 199,
                130, 145, 0, 0, 0, 25, 0, 0, 0, 99, 218, 117, 141, 230, 100, 69, 100, 173, 197,
                244, 185, 59, 232, 172, 205, 170, 0, 0, 0, 15, 0, 0, 0, 251, 182, 237, 116, 231,
                62, 68, 171, 136, 147, 66, 82, 121, 45, 115, 122, 185, 0, 0, 0, 6, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                5, 5, 5, 7, 7, 7, 7, 7, 7,
            ];
            let data: Vec<UAPI::CertTableEntry> = build_vec_uapi_cert_table();
            let actual: Vec<u8> = CertTableEntry::uapi_to_vec_bytes(&data).unwrap();
            assert_eq!(expected, actual);
        }

        #[test]
        fn test_parse_table_regular() {
            let mut cert_bytes: Vec<u8> = vec![
                192, 180, 6, 164, 168, 3, 73, 82, 151, 67, 63, 182, 1, 76, 208, 174, 120, 0, 0, 0,
                25, 0, 0, 0, 74, 183, 179, 121, 187, 172, 79, 228, 160, 47, 5, 174, 243, 39, 199,
                130, 145, 0, 0, 0, 25, 0, 0, 0, 99, 218, 117, 141, 230, 100, 69, 100, 173, 197,
                244, 185, 59, 232, 172, 205, 170, 0, 0, 0, 15, 0, 0, 0, 251, 182, 237, 116, 231,
                62, 68, 171, 136, 147, 66, 82, 121, 45, 115, 122, 185, 0, 0, 0, 6, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                5, 5, 5, 7, 7, 7, 7, 7, 7,
            ];

            let cert_bytes_ptr: *mut CertTableEntry =
                cert_bytes.as_mut_ptr() as *mut CertTableEntry;

            let actual: Vec<UAPI::CertTableEntry> =
                unsafe { CertTableEntry::parse_table(cert_bytes_ptr).unwrap() };

            let expected: Vec<UAPI::CertTableEntry> = build_vec_uapi_cert_table();

            assert_eq!(expected, actual);
        }

        #[test]
        #[should_panic]
        fn test_parse_table_offset_short() {
            let mut cert_bytes: Vec<u8> = vec![
                192, 180, 6, 164, 168, 3, 73, 82, 151, 67, 63, 182, 1, 76, 208, 174, 120, 0, 0, 0,
                1, 0, 0, 0, 74, 183, 179, 121, 187, 172, 79, 228, 160, 47, 5, 174, 243, 39, 199,
                130, 145, 0, 0, 0, 25, 0, 0, 0, 99, 218, 117, 141, 230, 100, 69, 100, 173, 197,
                244, 185, 59, 232, 172, 205, 170, 0, 0, 0, 15, 0, 0, 0, 251, 182, 237, 116, 231,
                62, 68, 171, 136, 147, 66, 82, 121, 45, 115, 122, 185, 0, 0, 0, 6, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                5, 5, 5, 7, 7, 7, 7, 7, 7,
            ];

            let cert_bytes_ptr: *mut CertTableEntry =
                cert_bytes.as_mut_ptr() as *mut CertTableEntry;

            let actual: Vec<UAPI::CertTableEntry> =
                unsafe { CertTableEntry::parse_table(cert_bytes_ptr).unwrap() };

            let expected: Vec<UAPI::CertTableEntry> = build_vec_uapi_cert_table();

            assert_eq!(
                expected, actual,
                "Invalid certificate offset encountered..."
            );
        }
    }
}
