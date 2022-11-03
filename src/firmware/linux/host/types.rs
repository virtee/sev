// SPDX-License-Identifier: Apache-2.0

use codicon::Read;

use crate::certs::sev;
use crate::firmware::uapi::host::types::{
    CertTable as UapiCertTable, CertTableEntry as UapiCertTableEntry, SnpCertError, SnpExtConfig,
    UserApiError,
};
use crate::Version;

use std::marker::PhantomData;
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
#[derive(Clone, Default)]
#[repr(C)]
pub struct CertTableEntry {
    /// Sixteen character GUID.
    guid: [u8; 16],

    /// The starting location of the certificate blob.
    offset: u32,

    /// The number of bytes to read from the offset.
    length: u32,
}

#[repr(C)]
pub struct CertTable {
    /// Pointer to the Certificates in question.
    entries: *const CertTableEntry,
}

impl Default for CertTable {
    fn default() -> Self {
        Self {
            entries: &CertTableEntry::default() as *const CertTableEntry,
        }
    }
}

impl CertTable {
    pub fn from_uapi(table: UapiCertTable) -> Result<Self, SnpCertError> {
        let mut entries: Vec<CertTableEntry> = vec![];
        let mut tmp_guid: [u8; 16] = [0u8; 16];

        for entry in table.entries {
            // We have a problem if the GUID is anything other than 16 bytes.
            if entry.guid().len() != 16 {
                return Err(SnpCertError::InvalidGUID);
            }

            // Copy the GUID into a byte array. Note: Unwrapping should be safe
            // here, as the value should be present.
            entry
                .guid()
                .as_bytes()
                .bytes()
                .zip(tmp_guid.iter_mut())
                .for_each(|(byte, ptr)| *ptr = byte.unwrap());

            // Push the entry onto the vector.
            entries.push(CertTableEntry {
                guid: tmp_guid,
                offset: entry.data().as_ptr() as *const u8 as u32,
                length: entry.data().len() as u32,
            });

            // Zero the tmp array.
            tmp_guid = [0; 16];
        }

        Ok(CertTable {
            entries: entries.as_ptr(),
        })
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
    unsafe fn parse_table(&self) -> Vec<UapiCertTableEntry> {
        const OFFSET_START: isize = (std::mem::size_of::<u8>() * 16) as isize;
        const LENGTH_START: isize = (std::mem::size_of::<u8>() * 20) as isize;
        const ENTRY_SIZE: isize = (std::mem::size_of::<u8>() * 24) as isize;
        const GUID_SIZE: usize = 16_usize;

        let mut retval: Vec<UapiCertTableEntry> = vec![];
        let mut guid_ptr: *const CertTableEntry = self.entries;
        let mut guid: String;
        let mut cert_address: *mut u8;
        let mut cert_len: usize;
        let mut cert_end: *mut u8;

        loop {
            let mut cert_bytes: Vec<u8> = vec![];

            // Calculate values for each CertTableEntry.
            cert_address = guid_ptr.offset(OFFSET_START) as *mut u8;
            cert_len = *(guid_ptr.offset(LENGTH_START) as *const usize);
            cert_end = cert_address.add(cert_len);
            guid = String::from_raw_parts(guid_ptr as *mut u8, GUID_SIZE, GUID_SIZE);

            // Gather the certificate bytes.
            while cert_address.ne(&cert_end) {
                cert_bytes.push(*cert_address);
                cert_address = cert_address.add(1);
            }

            // Append the entry to the vector.
            retval.push(UapiCertTableEntry::from_guid(&guid, cert_bytes));

            // Move the pointer ahead to the next value.
            guid_ptr = guid_ptr.offset(ENTRY_SIZE);

            // Check for the end of the table.
            if guid_ptr.eq(&std::ptr::null()) {
                break;
            }
        }

        retval
    }

    pub fn to_uapi(&self) -> UapiCertTable {
        UapiCertTable {
            entries: unsafe { self.parse_table() },
        }
    }
}

#[derive(Default)]
#[repr(C)]
pub struct SnpSetExtConfig {
    /// Address of the SnpConfig or 0 when reported_tcb does not need
    /// to be updated.
    pub config_address: u64,

    /// Address of extended guest request [`CertTable`] or 0 when
    /// previous certificate should be removed on SNP_SET_EXT_CONFIG.
    pub certs_address: u64,

    /// Length of the certificates.
    pub certs_len: u32,
}

impl SnpSetExtConfig {
    pub(crate) fn from_uapi(data: &SnpExtConfig) -> Result<Self, UserApiError> {
        Ok(Self {
            certs_address: if data.certs.is_none() {
                0
            } else {
                match CertTable::from_uapi(data.certs.clone().unwrap()) {
                    Ok(table) => &table as *const CertTable as u64,
                    Err(e) => return Err(UserApiError::ApiError(e)),
                }
            },
            config_address: if data.config.is_none() {
                0
            } else {
                &data.config.unwrap() as *const SnpConfig as u64
            },
            certs_len: if data.certs.is_none() {
                0
            } else {
                data.certs_len
            },
        })
    }
}

#[derive(Default)]
#[repr(C)]
pub struct SnpGetExtConfig {
    /// Address of the SnpConfig or 0 when reported_tcb should not be
    /// fetched.
    pub config_address: u64,

    /// Address of extended guest request [`CertTable`] or 0 when
    /// certificate should not be fetched.
    pub certs_address: u64,

    /// Length of the buffer which will hold the fetched certificates.
    pub certs_len: u32,
}

impl SnpGetExtConfig {
    pub(crate) fn as_uapi(&mut self) -> SnpExtConfig {
        SnpExtConfig {
            config: if self.config_address == 0 {
                None
            } else {
                let mut config: SnpConfig = Default::default();
                let ptr: *mut SnpConfig = &mut config;
                unsafe {
                    std::ptr::copy(self.config_address as *const SnpConfig, ptr, 1);
                    Some(*ptr)
                }
            },
            certs: if self.certs_address == 0 {
                None
            } else {
                let mut chain: CertTable = Default::default();
                let ptr: *mut CertTable = &mut chain;
                unsafe {
                    std::ptr::copy(self.certs_address as *const CertTable, ptr, 1);
                    Some((*ptr).to_uapi())
                }
            },
            certs_len: self.certs_len,
        }
    }
}
