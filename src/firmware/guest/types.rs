// SPDX-License-Identifier: Apache-2.0

use crate::{certs::snp::ecdsa::Signature, util::hexdump};

use std::fmt::Display;

use bitfield::bitfield;

#[cfg(feature = "serde")]
use serde_big_array::BigArray;

/// Structure of required data for fetching the derived key.
#[derive(Copy, Clone, Debug)]
pub struct DerivedKey {
    /// Selects the root key to derive the key from.
    /// 0: Indicates VCEK.
    /// 1: Indicates VMRK.
    root_key_select: u32,

    /// Reserved, must be zero
    _reserved_0: u32,

    /// What data will be mixed into the derived key.
    pub guest_field_select: GuestFieldSelect,

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
    /// Create a new instance for requesting an DerivedKey.
    pub fn new(
        root_key_select: bool,
        guest_field_select: GuestFieldSelect,
        vmpl: u32,
        guest_svn: u32,
        tcb_version: u64,
    ) -> Self {
        Self {
            root_key_select: u32::from(root_key_select),
            _reserved_0: Default::default(),
            guest_field_select,
            vmpl,
            guest_svn,
            tcb_version,
        }
    }

    /// Obtain a copy of the root key select value (Private Field)
    pub fn get_root_key_select(&self) -> u32 {
        self.root_key_select
    }
}

bitfield! {
    /// Data which will be mixed into the derived key.
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
    #[repr(C)]
    #[derive(Default, Copy, Clone)]
    pub struct GuestFieldSelect(u64);
    impl Debug;
    /// Check/Set guest policy inclusion in derived key.
    pub get_guest_policy, set_guest_policy: 0, 0;
    /// Check/Set image id inclusion in derived key.
    pub get_image_id, set_image_id: 1, 1;
    /// Check/Set family id inclusion in derived key.
    pub get_family_id, set_family_id: 2, 2;
    /// Check/Set measurement inclusion in derived key.
    pub get_measurement, set_measurement: 3, 3;
    /// Check/Set svn inclusion in derived key.
    pub get_svn, set_svn: 4, 4;
    /// Check/Set tcb version inclusion in derived key.
    pub get_tcb_version, set_tcb_version: 5, 5;
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
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
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
    /// Current TCB. See SNPTcbVersion
    pub current_tcb: TcbVersion,
    /// Information about the platform. See PlatformInfo
    pub plat_info: PlatformInfo,
    /// Private variable as only the first bit is important.
    /// See [`AttestationReport::_author_key_en`].
    _author_key_en: u32,
    _reserved_0: u32,
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    /// Guest-provided 512 Bits of Data
    pub report_data: [u8; 64],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    /// The measurement calculated at launch.
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    /// SHA-384 digest of the ID public key that signed the ID block provided
    /// in SNP_LANUNCH_FINISH.
    pub id_key_digest: [u8; 48],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    /// SHA-384 digest of the Author public key that certified the ID key,
    /// if provided in SNP_LAUNCH_FINSIH. Zeroes if AUTHOR_KEY_EN is 1.
    pub author_key_digest: [u8; 48],
    /// Report ID of this guest.
    pub report_id: [u8; 32],
    /// Report ID of this guest's migration agent (if applicable).
    pub report_id_ma: [u8; 32],
    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: TcbVersion,
    _reserved_1: [u8; 24],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    /// If MaskChipId is set to 0, Identifier unique to the chip.
    /// Otherwise set to 0h.
    pub chip_id: [u8; 64],
    /// CommittedTCB
    pub committed_tcb: TcbVersion,
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
    pub launch_tcb: TcbVersion,
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
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

#[cfg(all(feature = "openssl", feature = "serde"))]
impl Verifiable for (&Chain, &AttestationReport) {
    type Output = ();

    fn verify(self) -> io::Result<Self::Output> {
        let vcek = self.0.verify()?;

        let sig = EcdsaSig::try_from(&self.1.signature)?;
        let measurable_bytes: &[u8] = &bincode::serialize(self.1).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Unable to serialize bytes: {}", e),
            )
        })?[..0x2a0];

        let mut hasher = Sha384::new();
        hasher.update(measurable_bytes);
        let base_digest = hasher.finish();

        let ec = vcek.public_key()?.ec_key()?;
        let signed = sig.verify(&base_digest, &ec)?;

        match signed {
            true => Ok(()),
            false => Err(Error::new(
                ErrorKind::Other,
                "VCEK does not sign the attestation report",
            )),
        }
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
    /// | Bit(s) | Name          | Description                                                                                       >
    /// |--------|---------------|--------------------------------------------------------------------------------------------------->
    /// | 7:0    | ABI_MINOR     | The minimum ABI minor version required for this guest to run.                                     >
    /// | 15:8   | ABI_MAJOR     | The minimum ABI major version required for this guest to run.                                     >
    /// | 16     | SMT           | 0: Host SMT usage is disallowed.<br>1: Host SMT usage is allowed.                                 >
    /// | 17     | -             | Reserved. Must be one.                                                                            >
    /// | 18     | MIGRATE_MA    | 0: Association with a migration agent is disallowed.<br>1: Association with a migration agent is a>
    /// | 19     | DEBUG         | 0: Debugging is disallowed.<br>1: Debugging is allowed.                                           >
    /// | 20     | SINGLE_SOCKET | 0: Guest can be activated on multiple sockets.<br>1: Guest can only be activated on one socket.   >
    ///
    #[derive(Default, Clone, Copy)]
    #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
    #[repr(C)]
    pub struct GuestPolicy(u64);
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

impl Display for GuestPolicy {
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
            self.0,
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct TcbVersion {
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

impl Display for TcbVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
TCB Version:
  Microcode:   {}
  SNP:         {}
  TEE:         {}
  Boot Loader: {}
  "#,
            self.microcode, self.snp, self.tee, self.boot_loader
        )
    }
}

bitfield! {
    /// A structure with a bit-field unsigned 64 bit integer:
    /// Bit 0 representing the status of TSME enablement.
    /// Bit 1 representing the status of SMT enablement.
    /// Bits 2-63 are reserved.
    #[derive(Default, Clone, Copy)]
    #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
    #[repr(C)]
    pub struct PlatformInfo(u64);
    impl Debug;
    /// Returns the bit state of TSME.
    pub tsme_enabled, _: 0, 0;
    /// Returns the bit state of SMT
    pub smt_enabled, _: 1, 1;
}

impl Display for PlatformInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
Platform Info ({}):
  TSME Enabled: {}
  SMT Enabled:  {}
"#,
            self.0,
            self.tsme_enabled(),
            self.smt_enabled()
        )
    }
}
