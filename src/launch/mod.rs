// SPDX-License-Identifier: Apache-2.0

//! Everything one needs to launch an AMD SEV encrypted virtual machine.
//!
//! This module contains types for establishing a secure channel with the
//! AMD Secure Processor for purposes of attestation as well as abstractions
//! for navigating the AMD SEV launch process for a virtual machine.

#[cfg(target_os = "linux")]
mod linux;

pub mod sev;
pub mod snp;

use super::*;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::kvm::types::*;

bitflags! {
    /// Configurable SEV Policy options.
    #[derive(Default, Deserialize, Serialize)]
    pub struct PolicyFlags: u16 {
        /// When set, debugging the guest is forbidden.
        const NO_DEBUG        = 0b00000001u16.to_le();

        /// When set, sharing keys with other guests is prohibited.
        const NO_KEY_SHARING  = 0b00000010u16.to_le();

        /// When set, SEV-ES protections are required.
        const ENCRYPTED_STATE = 0b00000100u16.to_le();

        /// When set, the guest may not be sent to another platform.
        const NO_SEND         = 0b00001000u16.to_le();

        /// When set, the guest may not be transmitted to a platform
        /// that is outside of the domain.
        const DOMAIN          = 0b00010000u16.to_le();

        /// When set, the guest may not be transmitted to another
        /// platform that is not SEV-capable.
        const SEV             = 0b00100000u16.to_le();
    }
}

/// Describes a policy that the AMD Secure Processor will
/// enforce.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Policy {
    /// The various policy optons are encoded as bit flags.
    pub flags: PolicyFlags,

    /// The desired minimum platform firmware version.
    pub minfw: Version,
}

/// A secure channel between the tenant and the AMD Secure
/// Processor.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Used for deriving a shared secret between the tenant
    /// and the AMD SP.
    pub nonce: [u8; 16],

    /// The TEK and TIK concatenated together and wrapped by
    /// the Key Encryption Key and the Key Integrity Key.
    /// (KIK (KEK (TEK|TIK))).
    pub wrap_tk: [u8; 32],

    /// The initialization vector.
    pub wrap_iv: [u8; 16],

    /// Integrity protection for the wrapped keys (see the
    /// `wrap_tk` field of this struct).
    pub wrap_mac: [u8; 32],

    /// The integrity-protected SEV policy.
    pub policy_mac: [u8; 32],
}

/// Used to establish a secure session with the AMD SP.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Start {
    /// The tenant's policy for this SEV guest.
    pub policy: Policy,

    /// The tenant's Diffie-Hellman certificate.
    pub cert: certs::sev::Certificate,

    /// A secure channel with the AMD SP.
    pub session: Session,
}

impl codicon::Decoder<()> for Start {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, _: ()) -> std::io::Result<Self> {
        reader.load()
    }
}

impl codicon::Encoder<()> for Start {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.save(self)
    }
}

bitflags! {
    /// Additional descriptions of the secret header packet.
    #[derive(Default, Deserialize, Serialize)]
    pub struct HeaderFlags: u32 {
        /// If set, the contents of the packet are compressed and
        /// the AMD SP must decompress them.
        const COMPRESSED = 0b00000001u32.to_le();
    }
}

/// The header for a data packet that contains secret information
/// to be injected into the guest.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Header {
    /// Describes the secret packet (for example: if it is
    /// compressed).
    pub flags: HeaderFlags,

    /// The initialization vector.
    pub iv: [u8; 16],

    /// Integrity protection MAC.
    pub mac: [u8; 32],
}

/// A packet containing secret information to be injected
/// into the guest.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Secret {
    /// The header for this packet.
    pub header: Header,

    /// The encrypted secret to inject.
    pub ciphertext: Vec<u8>,
}

impl codicon::Decoder<()> for Secret {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, _: ()) -> std::io::Result<Self> {
        let header = reader.load()?;
        let mut ciphertext = vec![];
        let _ = reader.read_to_end(&mut ciphertext)?;
        Ok(Self { header, ciphertext })
    }
}

impl codicon::Encoder<()> for Secret {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.save(&self.header)?;
        writer.write_all(&self.ciphertext)
    }
}

/// A measurement of the SEV guest.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Measurement {
    /// The measurement.
    pub measure: [u8; 32],

    /// A random nonce.
    pub mnonce: [u8; 16],
}

impl codicon::Decoder<()> for Measurement {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, _: ()) -> std::io::Result<Self> {
        reader.load()
    }
}

impl codicon::Encoder<()> for Measurement {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.save(self)
    }
}

bitflags! {
    /// Configurable SNP Policy options.
    #[derive(Default, Deserialize, Serialize)]
    pub struct SnpPolicyFlags: u16 {
        /// Enable if SMT is enabled in the host machine.
        const SMT = 1;

        /// If enabled, association with a migration agent is allowed.
        const MIGRATE_MA = 1 << 2;

        /// If enabled, debugging is allowed.
        const DEBUG = 1 << 3;
    }
}

/// Describes a policy that the AMD Secure Processor will
/// enforce.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct SnpPolicy {
    /// The various policy optons are encoded as bit flags.
    pub flags: SnpPolicyFlags,

    /// The desired minimum platform firmware version.
    pub minfw: Version,
}

impl SnpPolicy {
    /// Convert a Policy to it's u64 counterpart.
    pub fn as_u64(&self) -> u64 {
        let mut val: u64 = 0;

        let minor_version = u64::from(self.minfw.minor);
        let mut major_version = u64::from(self.minfw.major);

        /*
         * According to the SNP firmware spec, bit 1 of the policy flags is reserved and must
         * always be set to 1. Rather than passing this responsibility off to callers, set this bit
         * every time an ioctl is issued to the kernel.
         */
        let flags = self.flags.bits | 0b10;
        let mut flags_64 = u64::from(flags);

        major_version <<= 8;
        flags_64 <<= 16;

        val |= minor_version;
        val |= major_version;
        val |= flags_64;
        val &= 0x00FFFFFF;

        val
    }
}

/// Encapsulates the various data needed to begin the launch process.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct SnpStart<'a> {
    /// The userspace address of the migration agent region to be encrypted.
    pub ma_uaddr: Option<&'a [u8]>,

    /// Describes a policy that the AMD Secure Processor will enforce.
    pub policy: SnpPolicy,

    /// Indicates if this guest is associated with a migration agent. Otherwise 0.
    pub ma_en: bool,

    /// Indicates that this launch flow is launching an IMI for the purpose of guest-assisted migration.
    pub imi_en: bool,

    /// Hypervisor provided value to indicate guest OS visible workarounds.The format is hypervisor defined.
    pub gosvw: [u8; 16],
}

impl<'a> SnpStart<'a> {
    /// Encapsulate all data needed for the SNP_LAUNCH_START ioctl.
    pub fn new(
        ma_uaddr: Option<&'a [u8]>,
        policy: SnpPolicy,
        imi_en: bool,
        gosvw: [u8; 16],
    ) -> Self {
        Self {
            ma_uaddr,
            policy,
            ma_en: ma_uaddr.is_some(),
            imi_en,
            gosvw,
        }
    }
}

/// Encapsulates the various data needed to begin the update process.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SnpUpdate<'a> {
    /// guest start frame number.
    pub start_gfn: u64,

    /// The userspace of address of the encrypted region.
    pub uaddr: &'a [u8],

    /// Indicates that this page is part of the IMI of the guest.
    pub imi_page: bool,

    /// Encoded page type.
    pub page_type: SnpPageType,

    /// VMPL3 permission mask.
    pub vmpl3_perms: VmplPerms,

    /// VMPL2 permission mask.
    pub vmpl2_perms: VmplPerms,

    /// VMPL1 permission mask.
    pub vmpl1_perms: VmplPerms,
}

impl<'a> SnpUpdate<'a> {
    /// Encapsulate all data needed for the SNP_LAUNCH_UPDATE ioctl.
    pub fn new(
        start_gfn: u64,
        uaddr: &'a [u8],
        imi_page: bool,
        page_type: SnpPageType,
        perms: (VmplPerms, VmplPerms, VmplPerms),
    ) -> Self {
        Self {
            start_gfn,
            uaddr,
            imi_page,
            page_type,
            vmpl3_perms: perms.2,
            vmpl2_perms: perms.1,
            vmpl1_perms: perms.0,
        }
    }
}

bitflags! {
    #[derive(Default, Deserialize, Serialize)]
    /// VMPL permission masks.
    pub struct VmplPerms: u8 {
        /// Page is readable by the VMPL.
        const READ = 1;

        /// Page is writeable by the VMPL.
        const WRITE = 1 << 1;

        /// Page is executable by the VMPL in CPL3.
        const EXECUTE_USER = 1 << 2;

        /// Page is executable by the VMPL in CPL2, CPL1, and CPL0.
        const EXECUTE_SUPERVISOR = 1 << 3;
    }
}

/// Encoded page types for a launch update. See Table 58 of the SNP Firmware
/// specification for further details.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
#[non_exhaustive]
pub enum SnpPageType {
    /// A normal data page.
    Normal = 0x1,

    /// A VMSA page.
    Vmsa = 0x2,

    /// A page full of zeroes.
    Zero = 0x3,

    /// A page that is encrypted but not measured
    Unmeasured = 0x4,

    /// A page for the firmware to store secrets for the guest.
    Secrets = 0x5,

    /// A page for the hypervisor to provide CPUID function values.
    Cpuid = 0x6,
}

/// Encapsulates the data needed to complete a guest launch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SnpFinish<'a, 'b> {
    /// The userspace address of the encrypted region.
    pub id_block: Option<&'a [u8]>,

    /// The userspace address of the authentication information of the ID block.
    pub id_auth: Option<&'b [u8]>,

    /// Indicates that the ID block is present.
    pub id_block_en: bool,

    /// Indicates that the author key is present in the ID authentication information structure.
    /// Ignored if id_block_en is 0.
    pub auth_key_en: bool,

    /// Opaque host-supplied data to describe the guest. The firmware does not interpret this
    /// value.
    pub host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],
}

impl<'a, 'b> SnpFinish<'a, 'b> {
    /// Encapsulate all data needed for the SNP_LAUNCH_FINISH ioctl.
    pub fn new(
        id_block: Option<&'a [u8]>,
        id_auth: Option<&'b [u8]>,
        host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],
    ) -> Self {
        Self {
            id_block,
            id_auth,
            id_block_en: id_block.is_some(),
            auth_key_en: id_auth.is_some(),
            host_data,
        }
    }
}
