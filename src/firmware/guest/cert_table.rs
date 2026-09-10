// SPDX-License-Identifier: Apache-2.0

//! Linux `sev-guest` certificate-table kernel wire format.
//!
//! [`KernelCertTableEntry`] is the `#[repr(C)]` layout the Linux kernel uses for
//! each header in an SNP extended-report certificate table. Serialization and
//! parsing of the full table operate on the public
//! [`CertTableEntry`](crate::types::snp::CertTableEntry) values returned to
//! callers; see [`CertTableEntry::cert_table_to_vec_bytes`] and
//! [`CertTableEntry::vec_bytes_to_cert_table`].

#[cfg(target_os = "linux")]
use crate::error::CertError;

use crate::types::snp::CertTableEntry;

#[cfg(target_os = "linux")]
use uuid::Uuid;

/// One header in the Linux kernel `cert_table_entry` chain.
///
/// Matches the C layout used by the `sev-guest` driver:
///
/// ```c
/// struct cert_table {
///     struct {
///         unsigned char guid[16];
///         uint32_t offset;
///         uint32_t length;
///     } cert_table_entry[];
/// };
/// ```
///
/// Certificate DER bytes follow the header chain. Offsets are measured from the
/// start of the table buffer. A zero GUID terminates the chain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct KernelCertTableEntry {
    guid: [u8; 16],
    offset: u32,
    length: u32,
}

impl KernelCertTableEntry {
    /// Serialize [`CertTableEntry`] values into the kernel certificate-table layout.
    ///
    /// Accepts the Rust-friendly [`CertTableEntry`] slice, appends a zero-GUID
    /// terminator entry, and concatenates the certificate payloads. Offsets are
    /// written in native endianness to match the kernel UAPI.
    ///
    /// The contiguous memory layout looks like this:
    ///
    /// ```text
    ///             |-> |------------------|    |- KernelCertTableEntry -|
    ///             |   | entry_1          |    | - guid                  |
    ///             |   | entry_2          |    | - offset                |
    /// CertTable --|   | ...              |    | - length                |
    ///             |   | ...              |    |-------------------------|
    ///             |-> | entry_z (zeroes) | <-- terminator
    /// offset (1)  --> | RawCertificate_1 |
    ///                 | ...              |
    /// offset (2)  --> | RawCertificate_2 |
    ///                 | ...              |
    /// offset (n)  --> | RawCertificate_n |
    ///                 |------------------|
    /// ```
    #[cfg(target_os = "linux")]
    pub fn uapi_to_vec_bytes(table: &[CertTableEntry]) -> Result<Vec<u8>, CertError> {
        let mut bytes: Vec<u8> = vec![];
        let mut offset: u32 =
            (std::mem::size_of::<KernelCertTableEntry>() * (table.len() + 1)) as u32;
        let mut raw_certificates: Vec<u8> = vec![];

        for entry in table {
            let guid: Uuid = match Uuid::parse_str(&entry.guid_string()) {
                Ok(uuid) => uuid,
                Err(_) => return Err(CertError::InvalidGUID),
            };

            bytes.extend_from_slice(guid.as_bytes());
            bytes.extend_from_slice(&offset.to_ne_bytes());
            bytes.extend_from_slice(&(entry.data().len() as u32).to_ne_bytes());
            raw_certificates.extend_from_slice(entry.data());
            offset += entry.data().len() as u32;
        }

        bytes.append(&mut vec![0u8; std::mem::size_of::<KernelCertTableEntry>()]);
        bytes.append(&mut raw_certificates);

        Ok(bytes)
    }

    /// Walk a null-terminated kernel certificate-table pointer chain.
    ///
    /// Parses the wire layout in guest memory and returns owned
    /// [`CertTableEntry`] values for attestation and endorser code.
    ///
    /// # Safety
    ///
    /// `data` must point to a valid, null-terminated kernel cert table in guest
    /// memory with correctly sized entries and certificate payloads.
    #[cfg(target_os = "linux")]
    pub unsafe fn parse_table(
        mut data: *mut KernelCertTableEntry,
    ) -> Result<Vec<CertTableEntry>, uuid::Error> {
        const ZERO_GUID: Uuid = Uuid::from_bytes([0x0; 16]);

        let table_ptr: *mut u8 = data as *mut u8;
        let mut retval: Vec<CertTableEntry> = vec![];

        loop {
            let entry = *data;
            let guid: Uuid = Uuid::from_slice(entry.guid.as_slice())?;

            if guid == ZERO_GUID {
                break;
            }

            let mut cert_bytes: Vec<u8> = vec![];
            let mut cert_addr: *mut u8 = table_ptr.offset(entry.offset as isize);
            let cert_end: *mut u8 = cert_addr.add(entry.length as usize);

            while cert_addr != cert_end {
                cert_bytes.push(*cert_addr);
                cert_addr = cert_addr.add(1);
            }

            retval.push(CertTableEntry::from_guid(&guid, cert_bytes)?);
            data = data.offset(1);
        }

        Ok(retval)
    }
}
