// SPDX-License-Identifier: Apache-2.0

use crate::certs::sev;
use crate::Version;

use std::ffi::c_void;
use std::marker::PhantomData;

#[cfg(feature = "openssl")]
use openssl::{bn::BigNum, ecdsa::EcdsaSig};
#[cfg(feature = "openssl")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "openssl")]
use serde_big_array::BigArray;

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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

#[repr(C)]
pub struct SnpConfig {
    reserved: [u8; 52],
}

impl Default for SnpConfig {
    fn default() -> Self {
        Self { reserved: [0; 52] }
    }
}

#[repr(C)]
pub struct SnpSetExtConfig<'a> {
    /// Address of the SnpConfig or 0 when reported_tcb does not need
    /// to be updated.
    pub config_address: Option<&'a SnpConfig>,

    /// Address of extended guest request certificate chain or 0 when
    /// previous certificate should be removed on SNP_SET_EXT_CONFIG.
    pub certs_address: Option<*mut c_void>,

    /// Length of the certificates.
    pub certs_len: u32,
}

#[repr(C)]
pub struct SnpGetExtConfig<'a> {
    /// Address of the SnpConfig or 0 when reported_tcb does not need
    /// to be updated.
    pub config_address: Option<&'a SnpConfig>,

    /// Address of extended guest request certificate chain or 0 when
    /// previous certificate should be removed on SNP_SET_EXT_CONFIG.
    pub certs_address: Option<*mut c_void>,

    /// Length of the certificates.
    pub certs_len: u32,
}

/// Locates the non-zero based index bit field of a specified number.
///
/// `$field`: expr - The number in question the bit should be taken from.
/// `$bit`: expr - The one-based index bit being requested.
/// `$dt`: ty - The data type of the field (for alignment reasons).
///
/// # Examples:
///
/// To find the 3rd bit field of Guest Field Select of a Derived Key Request:
///
/// ```
/// let mut key_req: DerivedKeyReq = Default::default();
/// key_req.guest_field_select = 4; /// 0b0..100 the third bit should be on.
/// let res = bit_val\!(key_req.guest_field_select, 3, u64);
/// assert_eq!(res, 1);
/// ```
///
#[macro_export]
macro_rules! bit_val {
    ($field: expr, $bit: expr, $dt: ty) => {
        {
            ($field & (1 as $dt << ($bit as $dt - 1 as $dt))) >> ($bit - 1 as $dt)
        }
    }
}

#[cfg(feature = "openssl")]
fn swap_endian(bytes: &mut [u8]) -> Vec<u8> {
    let mut retval: Vec<u8> = Vec::new();

    for byte in bytes.iter().rev() {
        retval.push(*byte);
    }
    retval
}

/// Information provided by the guest owner for requesting an attestation
/// report from the AMD Secure Processor.
#[repr(C)]
pub struct ReportReq {
    /// Guest-provided data to be included into the attestation report
    pub report_data: [u8; 64],

    /// The VMPL to put into the attestation report. Must be greater than or
    /// equal to the current VMPL and at most three.
    pub vmpl: u32,

    /// Reserved memory slot, but be zero.
    reserved: [u8; 28],
}

impl Default for ReportReq {
    fn default() -> Self {
        Self {
            report_data: [0; 64],
            vmpl: Default::default(),
            reserved: Default::default(),
        }
    }
}

/// The firmware associates each guest with a guest policy that the guest owner provides. The
/// firmware restricts what actions the hypervisor can take on this guest according to the guest policy.
/// The policy also indicates the minimum firmware version to for the guest.
///
/// The guest owner provides the guest policy to the firmware during launch. The firmware then binds
/// the policy to the guest. The policy cannot be changed throughout the lifetime of the guest. The
/// policy is also migrated with the guest and enforced by the destination platform firmware.
///
/// | Bit(s) | Name          | Description                                                                                                    |
/// |--------|---------------|----------------------------------------------------------------------------------------------------------------|
/// | 7:0    | ABI_MINOR     | The minimum ABI minor version required for this guest to run.                                                  |
/// | 15:8   | ABI_MAJOR     | The minimum ABI major version required for this guest to run.                                                  |
/// | 16     | SMT           | 0: SMT is disallowed.<br>1: SMT is allowed.                                                               |
/// | 17     | -             | Reserved. Must be one.                                                                                         |
/// | 18     | MIGRATE_MA    | 0: Association with a migration agent is disallowed.<br>1: Association with a migration agent is allowed. |
/// | 19     | DEBUG         | 0: Debugging is disallowed.<br>1: Debuggin is allowed.                                                   |
/// | 20     | SINGLE_SOCKET | 0: Guest can be activated on multiple sockets.<br>1: Guest can only be activated on one socket.           |
///
#[derive(Default, Clone, Copy, Debug)]
#[cfg_attr(feature = "openssl", derive(Serialize, Deserialize))]
#[repr(C)]
pub struct GuestPolicy {
    info: u64,
}

impl GuestPolicy {
    /// Bits 0-7 of Guest Policy's info
    pub fn abi_minor(&self) -> u64 {
        let mask: u64 = (1 << 8) - 1;
        self.info & mask
    }
    /// Bits 8-15 of Guest Policy's info
    pub fn abi_major(&self) -> u64 {
        let mask: u64 = ((1 << 8) - 1) << 8;
        (self.info & mask) >> 8
    }

    /// Bit 16 of Guest Policy's info
    pub fn smt(&self) -> bool {
        bit_val!(self.info, 16, u64) != 0
    }

    /// Bit 18 of Guest Policy's info
    pub fn single_socket(&self) -> bool {
        bit_val!(self.info, 18, u64) != 0
    }

    /// Bit 19 of Guest Policy's info
    pub fn debug(&self) -> bool {
        bit_val!(self.info, 19, u64) != 0
    }

    /// Bit 20 of Guest Policy's info
    pub fn migrate_ma(&self) -> bool {
        bit_val!(self.info, 20, u64) != 0
    }
}

/// The TCB_VERSION is a structure containing the security version numbers of each component in
/// the trusted computing base (TCB) of the SNP firmware. associated A TCB_VERSION is
/// associated with each image of firmware. T
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openssl", derive(Serialize, Deserialize))]

pub struct SNPTcbVersion {
    /// Current bootloader version. SVN of PSP Bootloader.
    pub boot_loader: u8,
    /// Current PSP OS version. SVN of PSP Operating System.
    pub tee: u8,
    reserved: [u8; 4],
    /// Version of the SNP firmware. Security Version Number (SVN) of SNP firmware.
    pub snp: u8,
    /// Lowest current patch level of all the cores.
    pub microcode: u8,
}

impl SNPTcbVersion {
    pub fn raw(&self) -> String {
        format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}{:02}{:02}",
            self.boot_loader,
            self.tee,
            self.reserved[3],
            self.reserved[2],
            self.reserved[1],
            self.reserved[0],
            self.snp,
            self.microcode,
        )
    }
}

/// A structure with a bit-field unsigned 64 bit integer:
/// Bit 0 representing the status of TSME enablement.
/// Bit 1 representing the status of SMT enablement.
/// Bits 2-63 are reserved.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "openssl", derive(Serialize, Deserialize))]
pub struct PlatformInfo {
    info: u64,
}

impl PlatformInfo {
    /// Returns the state of TSME
    pub fn tsme_en(&self) -> bool {
        bit_val!(self.info, 1, u64) != 0
    }

    /// Returns the state of SMT
    pub fn smt_en(&self) -> bool {
        bit_val!(self.info, 2, u64) != 0
    }
}

/// The format of an ECDSA P-384 with SHA-384 Signature.
#[repr(C)]
#[derive(Debug)]
#[cfg_attr(feature = "openssl", derive(Serialize, Deserialize))]
pub struct Signature {
    /// R component of this signature. Value is zero-extended little-endian encoded.
    #[cfg_attr(feature = "openssl", serde(with = "BigArray"))]
    pub r: [u8; 72],
    /// S component of this signature. Value is zero-extended little-endian encoded.
    #[cfg_attr(feature = "openssl", serde(with = "BigArray"))]
    pub s: [u8; 72],
    #[cfg_attr(feature = "openssl", serde(with = "BigArray"))]
    _reserved_0: [u8; 512 - 144],
}

#[cfg(feature = "openssl")]
impl Signature {
    pub fn get_ecdsa_sig(&mut self) -> EcdsaSig {
        // OpenSSL Expects BigNum values in Big Endian so use lebin2bn

        let r_rev: Vec<u8> = swap_endian(&mut self.r);
        let s_rev: Vec<u8> = swap_endian(&mut self.s);

        let bnr: BigNum = match BigNum::from_slice(&r_rev) {
            Ok(num) => num,
            Err(error) => panic!("Could not parse Signature 'r' as BigNum: {error}"),
        };

        let bns: BigNum = match BigNum::from_slice(&s_rev) {
            Ok(num) => num,
            Err(error) => panic!("Could not parse Signature 's' as BigNum: {error}"),
        };

        match EcdsaSig::from_private_components(bnr, bns) {
            Ok(sig) => sig,
            Err(error) => panic!("Unable to generate EcdsaSignature: {error}"),
        }
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            r: [0; 72],
            s: [0; 72],
            _reserved_0: [0; 368],
        }
    }
}

/// The guest can request that the firmware construct an attestation report. External entities can use an
/// attestation report to assure the identity and security configuration of the guest.
///
/// A guest requests an attestation report by constructing an MSGReportReq
/// The message contains data provided by the guest in REPORT_DATA to be included
/// into the report; the firmware does not interpret this data.
///
/// Upon receiving a request for an attestation report, the PSP creates one.
///
/// The firmware generates a report ID for each guest that persists with the guest instance throughout
/// its lifetime. In each attestation report, the report ID is placed in REPORT_ID. If the guest has a
/// migration agent associated with it, the REPORT_ID_MA is filled in with the report ID of the
/// migration agent.
///
/// The firmware signs the attestation report with its VCEK. The firmware uses the system wide
/// ReportedTcb value as the TCB version to derive the VCEK. This value is set by the hypervisor.
///
/// The firmware guarantees that the ReportedTcb value is never greater than the installed TCB
/// version
#[repr(C)]
#[derive(Debug)]
#[cfg_attr(feature = "openssl", derive(Serialize, Deserialize))]
pub struct AttestationReport {
    /// Version number of this attestation report. Set to 2h for this specification.
    pub version: u32,
    /// The guest SVN.
    pub guest_svn: u32,
    /// The guest policy.
    pub policy: GuestPolicy,
    /// The family ID provided at launch.
    pub family_id: [u8; 16],
    /// The image ID provided at launch.
    pub image_id: [u8; 16],
    /// The request VMPL for the attestation report.
    pub vmpl: u32,
    /// The signature algorithm used to sign this report.
    pub sig_algo: u32,
    /// Current TCB. See [`SNPTcbVersion`]
    pub current_tcb: SNPTcbVersion,
    /// Information about the platform. See [`PlatformInfo`]
    pub plat_info: PlatformInfo,
    /// Private variable as only the first bit is important.
    /// See [`AttestationReport::author_key_en`].
    author_key_en: u32,
    _reserved_0: u32,
    /// Guest-provided 512 Bits of Data
    #[cfg_attr(feature = "openssl", serde(with = "BigArray"))]
    pub report_data: [u8; 64],
    /// The measurement calculated at launch.
    #[cfg_attr(feature = "openssl", serde(with = "BigArray"))]
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32],
    /// SHA-384 digest of the ID public key that signed the ID block provided
    /// in SNP_LANUNCH_FINISH.
    #[cfg_attr(feature = "openssl", serde(with = "BigArray"))]
    pub id_key_digest: [u8; 48],
    /// SHA-384 digest of the Author public key that certified the ID key,
    /// if provided in SNP_LAUNCH_FINSIH. Zeroes if AUTHOR_KEY_EN is 1.
    #[cfg_attr(feature = "openssl", serde(with = "BigArray"))]
    pub author_key_digest: [u8; 48],
    /// Report ID of this guest.
    pub report_id: [u8; 32],
    /// Report ID of this guest's migration agent (if applicable).
    pub report_id_ma: [u8; 32],
    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: SNPTcbVersion,
    _reserved_1: [u8; 24],
    /// If MaskChipId is set to 0, Identifier unique to the chip.
    /// Otherwise set to 0h.
    #[cfg_attr(feature = "openssl", serde(with = "BigArray"))]
    pub chip_id: [u8; 64],
    /// CommittedTCB
    pub committed_tcb: SNPTcbVersion,
    /// The build number of CurrentVersion
    pub current_build: u8,
    /// The minor number of CurrentVersion
    pub current_minor: u8,
    /// The major number of CurrentVersion
    pub current_major: u8,
    _reserved_2: u8,
    /// The build number of CommittedVersion
    pub committed_build: u8,
    /// The minor number of CommittedVersion
    pub committed_minor: u8,
    /// The major number of CommittedVersion
    pub committed_major: u8,
    _reserved_3: u8,
    /// The CurrentTcb at the time the guest was launched or imported.
    pub launch_tcb: SNPTcbVersion,
    #[cfg_attr(feature = "openssl", serde(with = "BigArray"))]
    _reserved_4: [u8; 168],
    /// Signature of bytes 0 to 0x29F inclusive of this report.
    /// The format of the signature is found within [`Signature`].
    pub signature: Signature,
}

/// The response from the PSP containing the generated attestation report.
/// According to the kernel, this should match [`self::guest::ReportRsp`].
/// The Report is padded to exactly 4000 Bytes to make sure the page size
/// matches.
///
///
/// ```txt
///     96 Bytes (*Message Header)
/// + 4000 Bytes (*Encrypted Message)
/// ------------
///   4096 Bytes (4k Memory Page Alignment)
/// ```
/// <sup>*[Message Header - 8.26 SNP_GUEST_REQUEST - Table 97](<https://www.amd.com/system/files/TechDocs/56860.pdf#page=113>)</sup>
///
/// <sup>*[Encrypted Message - sev-guest.h](<https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/tree/include/uapi/linux/sev-guest.h>)</sup>
#[repr(C)]
pub struct MsgReportRsp {
    /// The status of key derivation operation.
    ///     0h: Success.
    ///     16h: Invalid parameters.
    pub status: u32,
    /// Size in bytes of the report.
    pub report_size: u32,
    reserved_0: [u8; 24],
    /// The attestation report generated by the firmware.
    pub report: AttestationReport,
    /// Padding bits to meet the memory page alignment.
    reserved_1: [u8; 2780],
}

/// The structure used to define the read/write data for the IOCTL
/// SNP_GUEST_REPORT.
#[repr(C)]
pub struct GuestMsg<'a, 'b> {
    /// Message version number (must be non-zero)
    pub msg_version: u8,

    /// Request structure address.
    pub req_data: &'a mut ReportReq,

    /// Response structure address.
    pub rsp_data: &'b mut MsgReportRsp,

    /// Firmware error.
    pub fw_err: u64,
}

/// Corresponds to MSG_KEY_REQ in the Spec. The message structure that the guest sends to the firmware to
/// request a derived key.
#[repr(C)]
pub struct DerivedKey {
    /// Selects the root key to derive the key from.
    /// 0: Indicates VCEK.
    /// 1: Indicates VMRK.
    root_key_select: u32,
    /// Reserved, must be zero
    reserved_0: u32,
    /// Bitmask indicating which data will be mixed into the derived key.
    ///
    /// | Bit(s) | Name | Description |
    /// |--------|------|-------------|
    /// |0|GUEST_POLICY|Indicates that the guest policy will be mixed into the key.|
    /// |1|IMAGE_ID|Indicates that the image ID of the guest will be mixed into the key.|
    /// |2|FAMILY_ID|Indicates the family ID of the guest will be mixed into the key.|
    /// |3|MEASUREMENT|Indicates the measurement of the guest during launch will be mixed into the key.|
    /// |4|GUEST_SVN|Indicates that the guest-provided SVN will be mixed into the key.|
    /// |5|TCB_VERSION|Indicates that the guest-provided TCB_VERSION will be mixed into the key.|
    /// |63:6|\-|Reserved. Must be zero.|
    guest_field_select: u64,
    /// The VMPL to mix into the derived key. Must be greater than or equal
    /// to the current VMPL.
    pub vmpl: u32,
    /// The guest SVN to mix into the key. Must not exceed the guest SVN
    /// provided at launch in the ID block.
    pub guest_svn: u32,
    /// The TCB version to mix into the derived key. Must not
    /// exceed CommittedTcb.
    pub tcb_version: u64,
}

impl DerivedKey {
    /// Determines the root key selected.
    ///
    /// `false`: Indicates VCEK.
    ///
    /// `true`:  Indicates VMRK.
    pub fn root_key_select(&self) -> bool {
        bit_val!(self.root_key_select, 1, u32) != 0
    }

    /// Retreive the raw guest_field_select value.
    pub fn guest_field_select(&self) -> u64 {
        self.guest_field_select
    }

    /// Checks if the Guest Field Select included the Guest Policy in the
    /// derived key.
    pub fn gfs_uses_guest_policy(&self) -> bool {
        bit_val!(self.guest_field_select, 1, u64) != 0
    }

    /// Checks if the Guest Field Select included the Image ID in the
    /// derived key.
    pub fn gfs_uses_image_id(&self) -> bool {
        bit_val!(self.guest_field_select, 2, u64) != 0
    }

    /// Checks if the Guest Field Select included the Family ID in the
    /// derived key.
    pub fn gfs_uses_family_id(&self) -> bool {
        bit_val!(self.guest_field_select, 3, u64) != 0
    }

    /// Checks if the Guest Field Select included the Launch Measurement in the
    /// derived key.
    pub fn gfs_uses_measurement(&self) -> bool {
        bit_val!(self.guest_field_select, 4, u64) != 0
    }

    /// Checks if the Guest Field Select included the Guest SVN in the
    /// derived key.
    pub fn gfs_uses_guest_svn(&self) -> bool {
        bit_val!(self.guest_field_select, 5, u64) != 0
    }

    /// Checks if the Guest Field Select included the TCB Version in the
    /// derived key.
    pub fn gfs_uses_tcb_version(&self) -> bool {
        bit_val!(self.guest_field_select, 6, u64) != 0
    }
}

/// A raw representation of the PSP Report Response after calling SNP_GET_DERIVED_KEY.
#[repr(C)]
pub struct DerivedKeyRsp {
    /// Response data, see SEV-SNP spec for the format
    pub data: [u8; 64],
}

#[repr(C)]
pub struct ExtReport {
    data: ReportReq,
    certs_address: *mut c_void,
    certs_len: u32,
}
