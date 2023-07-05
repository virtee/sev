// SPDX-License-Identifier: Apache-2.0

use crate::{error::CertError, firmware::host as UAPI};

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
    /// Users should pass the rust-friendly vector of [`UAPI::CertTableEntry`], and this function
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
    pub fn uapi_to_vec_bytes(table: &mut Vec<UAPI::CertTableEntry>) -> Result<Vec<u8>, CertError> {
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

#[repr(C)]
pub struct SnpSetExtConfig {
    /// Address of the Config or 0 when reported_tcb does not need
    /// to be updated.
    pub config_address: u64,

    /// Address of extended guest request [`CertTableEntry`] buffer or 0 when
    /// previous certificate(s) should be removed via SNP_SET_EXT_CONFIG.
    pub certs_address: u64,

    /// 4K-page aligned length of the buffer holding certificates to be cached.
    pub certs_len: u32,
}

#[repr(C)]
pub struct SnpGetExtConfig {
    /// Address of the Config or 0 when reported_tcb should not be
    /// fetched.
    pub config_address: u64,

    /// Address of extended guest request [`CertTableEntry`] buffer or 0 when
    /// certificate(s) should not be fetched.
    pub certs_address: u64,

    /// 4K-page aligned length of the buffer which will hold the fetched certificates.
    pub certs_len: u32,
}

#[cfg(test)]
mod test {
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
            let mut data: Vec<UAPI::CertTableEntry> = build_vec_uapi_cert_table();
            let actual: Vec<u8> = CertTableEntry::uapi_to_vec_bytes(&mut data).unwrap();
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
