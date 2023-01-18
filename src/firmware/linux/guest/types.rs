// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;

pub use crate::certs::sev::cert::v1::sig::ecdsa::Signature;
use crate::firmware::guest::types::SnpDerivedKey;
use bitfield::bitfield;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use static_assertions::const_assert;
use crate::util::hexdump;

pub(crate) const _4K_PAGE: usize = 4096;

#[repr(C)]
pub struct SnpDerivedKeyReq {
    /// Selects the root key to derive the key from.
    /// 0: Indicates VCEK.
    /// 1: Indicates VMRK.
    root_key_select: u32,

    /// Reserved, must be zero
    reserved_0: u32,

    /// What data will be mixed into the derived key.
    pub guest_field_select: u64,

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

impl SnpDerivedKeyReq {
    /// Create SnpDerivedKeyReq from UAPI SnpDerivedKey.
    ///
    /// # Arguments:
    ///
    /// * `derived_struct` - [`SnpDerivedKey`] a Rust-friendly structure to express the key derivision parameters.
    pub fn from_uapi(derived_struct: SnpDerivedKey) -> Self {
        Self {
            root_key_select: derived_struct.get_root_key_select(),
            reserved_0: Default::default(),
            guest_field_select: derived_struct.guest_field_select.0,
            vmpl: derived_struct.vmpl,
            guest_svn: derived_struct.guest_svn,
            tcb_version: derived_struct.tcb_version,
        }
    }
}

#[derive(Default)]
#[repr(C)]
/// A raw representation of the PSP Report Response after calling SNP_GET_DERIVED_KEY.
pub struct SnpDerivedKeyRsp {
    /// The status of key derivation operation.
    /// 0h: Success.
    /// 16h: Invalid parameters
    pub status: u32,

    reserved_0: [u8; 28],

    /// The requested derived key if [`DerivedKeyRsp::status`] is 0h.
    pub key: [u8; 32],
}

/// Information provided by the guest owner for requesting an attestation
/// report and associated certificate chain from the AMD Secure Processor.
///
/// The certificate buffer *should* be page aligned for the kernel.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SnpExtReportReq {
    /// Address of the [`SnpReportReq`].
    pub data: SnpReportReq,

    /// Starting address of the certificate data buffer.
    pub certs_address: u64,

    /// The page aligned length of the buffer the hypervisor should store the certificates in.
    pub certs_len: u32,
}

impl SnpExtReportReq {
    /// Creates a new exteded report with a one, 4K-page
    /// for the certs_address field and the certs_len field.
    pub fn new(data: SnpReportReq) -> Self {
        const _4K_PAGE: usize = 4096;
        Self {
            data,
            certs_address: vec![0u8; _4K_PAGE].as_mut_ptr() as u64,
            certs_len: _4K_PAGE as u32,
        }
    }

    /// This is used to update the certs_address offset when the buffer
    /// needs to be extended.This happens when more than one page is required
    /// for the storage.
    pub fn extend_buffer(&mut self) {
        self.certs_address = vec![0u8; self.certs_len as usize].as_mut_ptr() as u64;
    }
}

/// Information provided by the guest owner for requesting an attestation
/// report from the AMD Secure Processor.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SnpReportReq {
    /// Guest-provided data to be included int the attestation report
    pub report_data: [u8; 64],

    /// The VMPL to put into the attestation report. Must be greater than or
    /// equal to the current VMPL and at most three.
    pub vmpl: u32,

    /// Reserved memory slot, must be zero.
    reserved: [u8; 28],
}

impl Default for SnpReportReq {
    fn default() -> Self {
        Self {
            report_data: [0; 64],
            vmpl: Default::default(),
            reserved: Default::default(),
        }
    }
}

impl SnpReportReq {
    /// Instantiates a new [`SnpReportReq`] for fetching an [`AttestationReport`] from the PSP.
    ///
    /// # Arguments
    ///
    /// * `report_data` - (Optional) 64 bytes of unique data to be included in the generated report.
    /// * `vmpl` - The VMPL level the guest VM is running on.
    pub fn new(report_data: Option<[u8; 64]>, vmpl: u32) -> Self {
        Self {
            report_data: report_data.unwrap_or([0; 64]),
            vmpl,
            reserved: Default::default(),
        }
    }
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
///   4096 Bytes (4K Memory Page Alignment)
/// ```
/// <sup>*[Message Header - 8.26 SNP_GUEST_REQUEST - Table 97](<https://www.amd.com/system/files/TechDocs/56860.pdf#page=113>)</sup>
///
/// <sup>*[Encrypted Message - sev-guest.h](<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/sev-guest.h>)</sup>
#[repr(C)]
pub struct SnpReportRsp {
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
    reserved_1: [u8; 3152],
}

// Compile-time check that the size is what is expected.
// Will error out with:
//
//      evaluation of constant value failed attempt to compute
//      `0_usize - 1_usize`, which would overflow
//
const_assert!(std::mem::size_of::<SnpReportRsp>() == 4000);

impl Default for SnpReportRsp {
    fn default() -> Self {
        Self {
            status: Default::default(),
            report_size: Default::default(),
            reserved_0: Default::default(),
            report: Default::default(),
            reserved_1: [0; 3152],
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
#[derive(Deserialize, Serialize, Debug)]
pub struct AttestationReport {
    /// Version number of this attestation report. Set to 2h for this specification.
    pub version: u32,
    /// The guest SVN.
    pub guest_svn: u32,
    /// The guest policy.
    pub policy: SnpGuestPolicy,
    /// The family ID provided at launch.
    pub family_id: [u8; 16],
    /// The image ID provided at launch.
    pub image_id: [u8; 16],
    /// The request VMPL for the attestation report.
    pub vmpl: u32,
    /// The signature algorithm used to sign this report.
    pub sig_algo: u32,
    /// Current TCB. See SNPTcbVersion
    pub current_tcb: SnpTcbVersion,
    /// Information about the platform. See PlatformInfo
    pub plat_info: SnpPlatformInfo,
    /// Private variable as only the first bit is important.
    /// See [`AttestationReport::_author_key_en`].
    _author_key_en: u32,
    _reserved_0: u32,
    #[serde(with = "BigArray")]
    /// Guest-provided 512 Bits of Data
    pub report_data: [u8; 64],
    #[serde(with = "BigArray")]
    /// The measurement calculated at launch.
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32],
    #[serde(with = "BigArray")]
    /// SHA-384 digest of the ID public key that signed the ID block provided
    /// in SNP_LANUNCH_FINISH.
    pub id_key_digest: [u8; 48],
    #[serde(with = "BigArray")]
    /// SHA-384 digest of the Author public key that certified the ID key,
    /// if provided in SNP_LAUNCH_FINSIH. Zeroes if AUTHOR_KEY_EN is 1.
    pub author_key_digest: [u8; 48],
    /// Report ID of this guest.
    pub report_id: [u8; 32],
    /// Report ID of this guest's migration agent (if applicable).
    pub report_id_ma: [u8; 32],
    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: SnpTcbVersion,
    _reserved_1: [u8; 24],
    #[serde(with = "BigArray")]
    /// If MaskChipId is set to 0, Identifier unique to the chip.
    /// Otherwise set to 0h.
    pub chip_id: [u8; 64],
    /// CommittedTCB
    pub committed_tcb: SnpTcbVersion,
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
    pub launch_tcb: SnpTcbVersion,
    #[serde(with = "BigArray")]
    _reserved_4: [u8; 168],
    /// Signature of bytes 0 to 0x29F inclusive of this report.
    /// The format of the signature is found within Signature.
    pub signature: Signature,
}

impl AttestationReport {
    fn author_key_en(&self) -> bool {
        self._author_key_en == 1
    }
}

impl Default for AttestationReport {
    fn default() -> Self {
        Self {
            version: Default::default(),
            guest_svn: Default::default(),
            policy: Default::default(),
            family_id: Default::default(),
            image_id: Default::default(),
            vmpl: Default::default(),
            sig_algo: Default::default(),
            current_tcb: Default::default(),
            plat_info: Default::default(),
            _author_key_en: Default::default(),
            _reserved_0: Default::default(),
            report_data: [0; 64],
            measurement: [0; 48],
            host_data: Default::default(),
            id_key_digest: [0; 48],
            author_key_digest: [0; 48],
            report_id: Default::default(),
            report_id_ma: Default::default(),
            reported_tcb: Default::default(),
            _reserved_1: Default::default(),
            chip_id: [0; 64],
            committed_tcb: Default::default(),
            current_build: Default::default(),
            current_minor: Default::default(),
            current_major: Default::default(),
            _reserved_2: Default::default(),
            committed_build: Default::default(),
            committed_minor: Default::default(),
            committed_major: Default::default(),
            _reserved_3: Default::default(),
            launch_tcb: Default::default(),
            _reserved_4: [0; 168],
            signature: Default::default(),
        }
    }
}

impl Display for AttestationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Attestation Report ({} bytes):
Version:                      {}
Guest SVN:                    {}
{}
Family ID:                    {}
Image ID:                     {}
VMPL:                         {}
Signature Algorithm:          {}
Current TCB:
{}
{}
Author Key Encryption:        {}
Report Data:                  {}
Measurement:                  {}
Host Data:                    {}
ID Key Digest:                {}
Author Key Digest:            {}
Report ID:                    {}
Report ID Migration Agent:    {}
Reported TCB:                 {}
Chip ID:                      {}
Committed TCB:
{}
Current Build:                {}
Current Minor:                {}
Current Major:                {}
Committed Build:              {}
Committed Minor:              {}
Committed Major:              {}
Launch TCB:
{}
{}
"#,
            std::mem::size_of_val(self),
            self.version,
            self.guest_svn,
            self.policy,
            hexdump(&self.family_id),
            hexdump(&self.image_id),
            self.vmpl,
            self.sig_algo,
            self.current_tcb,
            self.plat_info,
            self.author_key_en(),
            hexdump(&self.report_data),
            hexdump(&self.measurement),
            hexdump(&self.host_data),
            hexdump(&self.id_key_digest),
            hexdump(&self.author_key_digest),
            hexdump(&self.report_id),
            hexdump(&self.report_id_ma),
            self.reported_tcb,
            hexdump(&self.chip_id),
            self.committed_tcb,
            self.current_build,
            self.current_minor,
            self.current_major,
            self.committed_build,
            self.committed_minor,
            self.committed_major,
            self.launch_tcb,
            self.signature
        )
    }
}

bitfield! {
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
    /// | 16     | SMT           | 0: Host SMT usage is disallowed.<br>1: Host SMT usage is allowed.                                                               |
    /// | 17     | -             | Reserved. Must be one.                                                                                         |
    /// | 18     | MIGRATE_MA    | 0: Association with a migration agent is disallowed.<br>1: Association with a migration agent is allowed. |
    /// | 19     | DEBUG         | 0: Debugging is disallowed.<br>1: Debugging is allowed.                                                   |
    /// | 20     | SINGLE_SOCKET | 0: Guest can be activated on multiple sockets.<br>1: Guest can only be activated on one socket.           |
    ///
    #[derive(Default, Deserialize, Serialize)]
    #[repr(C)]
    pub struct SnpGuestPolicy(u64);
    impl Debug;

    /// ABI_MINOR field: Indicates the minor API version.
    pub abi_minor, _: 7, 0;
    /// ABI_MAJOR field: Indicates the minor API version.
    pub abi_major, _: 15, 8;
    /// SMT_ALLOWED field: Indicates the if SMT should be permitted.
    pub smt_allowed, _: 16, 16;
    /// MIGRATE_MA_ALLOWED field: Indicates the if migration is permitted with
    /// the migration agent.
    pub migrate_ma_allowed, _: 18, 18;
    /// DEBUG_ALLOWED field: Indicates the if debugging should is permitted.
    pub debug_allowed, _: 19, 19;
    /// SINGLE_SOCKET_REQUIRED field: Indicates the if a single socket is required.
    pub single_socket_required, _: 20, 20;
}

impl Display for SnpGuestPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
  Guest Policy ({}):
    ABI Major:     {}
    ABI Minor:     {}
    SMT Allowed:   {}
    Migrate MA:    {}
    Debug Allowed: {}
    Single Socket: {}"#,
            self,
            self.abi_major(),
            self.abi_minor(),
            self.smt_allowed(),
            self.migrate_ma_allowed(),
            self.debug_allowed(),
            self.single_socket_required()
        )
    }
}

/// The TCB_VERSION is a structure containing the security version numbers of each component in
/// the trusted computing base (TCB) of the SNP firmware. A TCB_VERSION is associated with each
/// image of firmware.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]

pub struct SnpTcbVersion {
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

impl Display for SnpTcbVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
TCB Version:
  Raw:         {}
  Microcode:   {}
  SNP:         {}
  TEE:         {}
  Boot Loader: {}
  "#,
            *self,
            self.microcode,
            self.snp,
            self.tee,
            self.boot_loader
        )
    }
}

bitfield! {
    /// A structure with a bit-field unsigned 64 bit integer:
    /// Bit 0 representing the status of TSME enablement.
    /// Bit 1 representing the status of SMT enablement.
    /// Bits 2-63 are reserved.
    #[derive(Default, Deserialize, Serialize)]
    #[repr(C)]
    pub struct SnpPlatformInfo(u64);
    impl Debug;
    /// Returns the bit state of TSME.
    pub tsme_enabled, _: 0, 0;
    /// Returns the bit state of SMT
    pub smt_enabled, _: 1, 1;
}


impl Display for SnpPlatformInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Platform Info ({}):
  TSME Enabled: {}
  SMT Enabled:  {}
"#,
            *self,
            self.tsme_enabled(),
            self.smt_enabled()
        )
    }
}