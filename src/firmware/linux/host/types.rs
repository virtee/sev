// SPDX-License-Identifier: Apache-2.0

use crate::certs::sev;
use crate::firmware::host::types::{
    CertTableEntry as UapiCertTableEntry, SnpCertError, SnpExtConfig, UserApiError,
};
use crate::firmware::linux::guest::types::_4K_PAGE;
use crate::Version;

use std::marker::PhantomData;
use uuid::Uuid;

/// Reset the platform's persistent state.
///
/// (Chapter 5.5)
pub struct PlatformReset;

bitflags::bitflags! {
    /// The platform's status flags.
    #[derive(Default)]
    pub struct PlatformStatusFlags: u32 {
        /// If set, this platform is owned. Otherwise, it is self-owned.
        const OWNED           = 1 << 0;

        /// If set, encrypted state functionality is present.
        const ENCRYPTED_STATE = 1 << 8;
    }
}

/// Query SEV platform status.
///
/// (Chapter 5.6; Table 17)
#[derive(Default)]
#[repr(C, packed)]
pub struct PlatformStatus {
    /// The firmware version (major.minor)
    pub version: Version,

    /// The Platform State.
    pub state: u8,

    /// Right now the only flag that is communicated in
    /// this single byte is whether the platform is self-
    /// owned or not. If the first bit is set then the
    /// platform is externally owned. If it is cleared, then
    /// the platform is self-owned. Self-owned is the default
    /// state.
    pub flags: PlatformStatusFlags,

    /// The firmware build ID for this API version.
    pub build: u8,

    /// The number of valid guests maintained by the SEV firmware.
    pub guest_count: u32,
}

/// Generate a new Platform Endorsement Key (PEK).
///
/// (Chapter 5.7)
pub struct PekGen;

/// Request certificate signing.
///
/// (Chapter 5.8; Table 27)
#[repr(C, packed)]
pub struct PekCsr<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> PekCsr<'a> {
    pub fn new(cert: &'a mut sev::Certificate) -> Self {
        Self {
            addr: cert as *mut _ as _,
            len: std::mem::size_of_val(cert) as _,
            _phantom: PhantomData,
        }
    }
}

/// Join the platform to the domain.
///
/// (Chapter 5.9; Table 29)
#[repr(C, packed)]
pub struct PekCertImport<'a> {
    pek_addr: u64,
    pek_len: u32,
    oca_addr: u64,
    oca_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> PekCertImport<'a> {
    pub fn new(pek: &'a sev::Certificate, oca: &'a sev::Certificate) -> Self {
        Self {
            pek_addr: pek as *const _ as _,
            pek_len: std::mem::size_of_val(pek) as _,
            oca_addr: oca as *const _ as _,
            oca_len: std::mem::size_of_val(oca) as _,
            _phantom: PhantomData,
        }
    }
}

/// (Re)generate the Platform Diffie-Hellman (PDH).
///
/// (Chapter 5.10)
pub struct PdhGen;

/// Retrieve the PDH and the platform certificate chain.
///
/// (Chapter 5.11)
#[repr(C, packed)]
pub struct PdhCertExport<'a> {
    pdh_addr: u64,
    pdh_len: u32,
    certs_addr: u64,
    certs_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> PdhCertExport<'a> {
    pub fn new(pdh: &'a mut sev::Certificate, certs: &'a mut [sev::Certificate; 3]) -> Self {
        Self {
            pdh_addr: pdh as *mut _ as _,
            pdh_len: std::mem::size_of_val(pdh) as _,
            certs_addr: certs.as_mut_ptr() as _,
            certs_len: std::mem::size_of_val(certs) as _,
            _phantom: PhantomData,
        }
    }
}

/// Get the CPU's unique ID that can be used for getting
/// a certificate for the CEK public key.
#[repr(C, packed)]
pub struct GetId<'a> {
    id_addr: u64,
    id_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> GetId<'a> {
    pub fn new(id: &'a mut [u8; 64]) -> Self {
        Self {
            id_addr: id.as_mut_ptr() as _,
            id_len: id.len() as _,
            _phantom: PhantomData,
        }
    }

    /// This method is only meaningful if called *after* the GET_ID2 ioctl is called because the
    /// kernel will write the length of the unique CPU ID to `GetId.id_len`.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.id_addr as *const u8, self.id_len as _) }
    }
}

/// TcbVersion represents the version of the firmware.
///
/// (Chapter 2.2; Table 3)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct TcbVersion {
    /// Current bootloader version.
    /// SVN of PSP bootloader.
    pub bootloader: u8,
    /// Current PSP OS version.
    /// SVN of PSP operating system.
    pub tee: u8,
    _reserved: [u8; 4],
    /// Version of the SNP firmware.
    /// Security Version Number (SVN) of SNP firmware.
    pub snp: u8,
    /// Lowest current patch level of all the cores.
    pub microcode: u8,
}

impl TcbVersion {
    /// Creates a new isntance of a TcbVersion
    pub fn new(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        Self {
            bootloader,
            tee,
            snp,
            microcode,
            _reserved: Default::default(),
        }
    }
}

/// Query the SEV-SNP platform status.
///
/// (Chapter 8.3; Table 38)
#[derive(Default)]
#[repr(C)]
pub struct SnpPlatformStatus {
    /// The firmware API version (major.minor)
    pub version: Version,

    /// The platform state.
    pub state: u8,

    /// IsRmpInitiailzied
    pub is_rmp_init: u8,

    /// The platform build ID.
    pub build_id: u32,

    /// MaskChipId
    pub mask_chip_id: u32,

    /// The number of valid guests maintained by the SEV-SNP firmware.
    pub guest_count: u32,

    /// Installed TCB version.
    pub platform_tcb_version: TcbVersion,

    /// Reported TCB version.
    pub reported_tcb_version: TcbVersion,
}

/// Sets the system wide configuration values for SNP.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SnpConfig {
    /// The TCB_VERSION to report in guest attestation reports.
    pub reported_tcb: TcbVersion,

    /// Indicates that the CHIP_ID field in the attestationr eport will always
    /// be zero.
    pub mask_chip_id: u32,

    /// Reserved. Must be zero.
    reserved: [u8; 52],
}

impl Default for SnpConfig {
    fn default() -> Self {
        Self {
            reported_tcb: Default::default(),
            mask_chip_id: Default::default(),
            reserved: [0; 52],
        }
    }
}

impl SnpConfig {
    /// Used to create a new SnpConfig
    pub fn new(reported_tcb: TcbVersion, mask_chip_id: u32) -> Self {
        Self {
            reported_tcb,
            mask_chip_id,
            reserved: [0; 52],
        }
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
#[derive(Clone, Copy, Default, Debug)]
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
    /// Users should pass the rust-friendly vector of [`UapiCertTableEntry`], and this function
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
    pub fn uapi_to_vec_bytes(table: &mut Vec<UapiCertTableEntry>) -> Result<Vec<u8>, SnpCertError> {
        // Create the vector to return for later.
        let mut bytes: Vec<u8> = vec![];

        // Find the location where the first certificate should begin.
        let mut offset: u32 = (std::mem::size_of::<CertTableEntry>() * (table.len() + 1)) as u32;

        // Create the buffer to store the table and certificates.
        let mut raw_certificates: Vec<u8> = vec![];

        for entry in table.iter() {
            let guid: Uuid = match Uuid::parse_str(&entry.guid()) {
                Ok(uuid) => uuid,
                Err(_) => return Err(SnpCertError::InvalidGUID),
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
    ) -> Result<Vec<UapiCertTableEntry>, uuid::Error> {
        // Helpful Constance for parsing the data
        const ZERO_GUID: Uuid = Uuid::from_bytes([0x0; 16]);

        // Pre-defined re-usable variables.
        let table_ptr: *mut u8 = data as *mut u8;

        // Create a location to store the final data.
        let mut retval: Vec<UapiCertTableEntry> = vec![];

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
            let mut cert_addr: *mut u8 = table_ptr.offset(entry.offset as isize) as *mut u8;
            let cert_end: *mut u8 = cert_addr.add(entry.length as usize) as *mut u8;

            // Gather the certificate bytes.
            while cert_addr.ne(&cert_end) {
                cert_bytes.push(*cert_addr);
                cert_addr = cert_addr.add(1usize);
            }

            // Build the Rust-friendly structure and append vector to be returned when
            // we are finished.
            retval.push(UapiCertTableEntry::from_guid(
                &guid.hyphenated().to_string(),
                cert_bytes.clone(),
            ));

            // Move the pointer ahead to the next value.
            data = data.offset(1isize);
        }

        Ok(retval)
    }
}

#[derive(Default)]
#[repr(C)]
pub struct SnpSetExtConfig {
    /// Address of the SnpConfig or 0 when reported_tcb does not need
    /// to be updated.
    pub config_address: u64,

    /// Address of extended guest request [`CertTableEntry`] buffer or 0 when
    /// previous certificate(s) should be removed via SNP_SET_EXT_CONFIG.
    pub certs_address: u64,

    /// 4K-page aligned length of the buffer holding certificates to be cached.
    pub certs_len: u32,
}

impl SnpSetExtConfig {
    pub(crate) fn from_uapi(
        data: &SnpExtConfig,
        bytes: &mut Vec<u8>,
    ) -> Result<Self, UserApiError> {
        // Make sure the buffer is is of sufficient size.
        if data.certs_len < bytes.len() as u32 {
            return Err(UserApiError::ApiError(SnpCertError::BufferOverflow));
        }

        // Make sure the buffer length is 4K-page aligned.
        if data.certs_len > 0 && data.certs_len as usize % _4K_PAGE != 0 {
            return Err(UserApiError::ApiError(SnpCertError::PageMisalignment));
        }

        // Build a default instance, and then set the values as they have been provided.
        let mut retval: Self = Self::default();

        // When a configuration is present, make sure to copy the pointer.
        if data.config.is_some() {
            retval.config_address = &mut data.config.unwrap() as *mut SnpConfig as u64;
        }

        // When certificates are present, create a pointer to the location, and update the length appropriately.
        if data.certs.is_some() {
            // Update the bytes vector with correct bytes.
            *bytes = CertTableEntry::uapi_to_vec_bytes(&mut data.certs.clone().unwrap())?;

            // Set the pointers to the updated buffer.
            retval.certs_address = bytes.as_mut_ptr() as u64;
            retval.certs_len = data.certs_len;
        }

        Ok(retval)
    }
}

#[derive(Default)]
#[repr(C)]
pub struct SnpGetExtConfig {
    /// Address of the SnpConfig or 0 when reported_tcb should not be
    /// fetched.
    pub config_address: u64,

    /// Address of extended guest request [`CertTableEntry`] buffer or 0 when
    /// certificate(s) should not be fetched.
    pub certs_address: u64,

    /// 4K-page aligned length of the buffer which will hold the fetched certificates.
    pub certs_len: u32,
}

impl SnpGetExtConfig {
    pub(crate) fn as_uapi(&mut self) -> Result<SnpExtConfig, uuid::Error> {
        Ok(SnpExtConfig {
            config: if self.config_address == 0 {
                None
            } else {
                unsafe { Some(*(self.config_address as *mut SnpConfig)) }
            },
            certs: if self.certs_address == 0 {
                None
            } else {
                unsafe {
                    Some(CertTableEntry::parse_table(
                        self.certs_address as *mut CertTableEntry,
                    )?)
                }
            },
            certs_len: self.certs_len,
        })
    }
}
