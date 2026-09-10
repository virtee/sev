// SPDX-License-Identifier: Apache-2.0

//! SNP guest policy bitfield set at launch.
//!
//! [`GuestPolicy`] is bound to a guest for its lifetime and enforced by the
//! firmware on every migration. It appears in the ID block, attestation reports,
//! and launch reference measurements. Reserved-bit validation is
//! [`FirmwareVersion`](crate::types::shared::FirmwareVersion)-aware.

use crate::types::shared::FirmwareVersion;
use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};
use std::{
    fmt::Display,
    io::{Read, Write},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use bitfield::bitfield;
bitfield! {
    /// The firmware associates each guest with a guest policy that the guest owner provides. The
    /// firmware restricts what actions the hypervisor can take on this guest according to the guest policy.
    /// The policy also indicates the minimum firmware version to for the guest.
    ///
    /// The guest owner provides the guest policy to the firmware during launch. The firmware then binds
    /// the policy to the guest. The policy cannot be changed throughout the lifetime of the guest. The
    /// policy is also migrated with the guest and enforced by the destination platform firmware.
    ///
    /// | Bit(s) | Name              | Description                                                                                                        >
    /// |--------|-------------------|-------------------------------------------------------------------------------------------------------------------->
    /// | 7:0    | ABI_MINOR         | The minimum ABI minor version required for this guest to run.                                                      >
    /// | 15:8   | ABI_MAJOR         | The minimum ABI major version required for this guest to run.                                                      >
    /// | 16     | SMT               | 0: Host SMT usage is disallowed.<br>1: Host SMT usage is allowed.                                                  >
    /// | 17     | -                 | Reserved. Must be one.                                                                                             >
    /// | 18     | MIGRATE_MA        | 0: Association with a migration agent is disallowed.<br>1: Association with a migration agent is allowed           >
    /// | 19     | DEBUG             | 0: Debugging is disallowed.<br>1: Debugging is allowed.                                                            >
    /// | 20     | SINGLE_SOCKET     | 0: Guest can be activated on multiple sockets.<br>1: Guest can only be activated on one socket.                    >
    /// | 21     | CXL_ALLOW         | 0: CXL cannot be populated with devices or memory.<br>1: CXL can be populated with devices or memory.              >
    /// | 22     | MEM_AES_256_XTS   | 0: Allow either AES 128 XEX or AES 256 XTS for memory encryption.<br>1: Require AES 256 XTS for memory encryption. >
    /// | 23     | RAPL_DIS          | 0: Allow Running Average Power Limit (RAPL).<br>1: RAPL must be disabled.                                          >
    /// | 24     | CIPHERTEXT_HIDING | 0: Ciphertext hiding may be enabled or disabled.<br>1: Ciphertext hiding must be enabled.                          >
    /// | 25     | PAGE_SWAP_DISABLE | 0: Disable Guest access to SNP_PAGE_MOVE, SNP_SWAP_OUT and SNP_SWAP_IN commands.                                   >
    /// | 63:25  | -                 | Reserved. MBZ.                                                                                                     >
    ///
    #[repr(C)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
    pub struct GuestPolicy(u64);
    impl Debug;
    /// ABI_MINOR field: Indicates the minor API version.
    pub abi_minor, set_abi_minor: 7, 0;
    /// ABI_MAJOR field: minimum major ABI version required for this guest.
    pub abi_major, set_abi_major: 15, 8;
    /// SMT_ALLOWED field: Indicates the if SMT should be permitted.
    pub smt_allowed, set_smt_allowed: 16;
    /// MIGRATE_MA_ALLOWED field: Indicates the if migration is permitted with
    /// the migration agent.
    pub migrate_ma_allowed, set_migrate_ma_allowed: 18;
    /// DEBUG_ALLOWED field: Indicates the if debugging should is permitted.
    pub debug_allowed, set_debug_allowed: 19;
    /// SINGLE_SOCKET_REQUIRED field: Indicates the if a single socket is required.
    pub single_socket_required, set_single_socket_required: 20;
    /// CXL_ALLOW field: (1) can populate CXL devices/memory, (0) cannot populate CXL devices/memory
    pub cxl_allowed, set_cxl_allowed: 21;
    /// MEM_AES_256_XTS field: (1) require AES 256 XTS encryption, (0) allows either AES 128 XEX or AES 256 XTS encryption
    pub mem_aes_256_xts, set_mem_aes_256_xts: 22;
    /// RAPL_DIS field: (1) RAPL must be disabled, (0) allow RAPL
    pub rapl_dis, set_rapl_dis: 23;
    /// CIPHERTEXT_HIDING field: (1) ciphertext hiding must be enabled, (0) ciphertext hiding may be enabled/disabled
    pub ciphertext_hiding, set_ciphertext_hiding: 24;
    /// Guest policy to disable Guest access to SNP_PAGE_MOVE, SNP_SWAP_OUT, and SNP_SWAP_IN commands. If this policy
    /// option is selected to disable these Page Move commands, then these commands will return POLICY_FAILURE.
    /// 0: Do not disable Guest support for the commands.
    /// 1: Disable Guest support for the commands.
    ///
    /// **Since:** Report v5+
    pub page_swap_disabled, set_page_swap_disabled: 25;
}

impl GuestPolicy {
    const RMB1_BIT_17: u64 = 1u64 << 17;
    const RESERVED_MBZ_MASK_26_63: u64 = (!0u64) << 26; // bits 26..63

    // Bit 21: CXL_ALLOW (added in v1.55)
    const CXL_ALLOW_BIT_21: u64 = 1u64 << 21;
    // Bit 22: MEM_AES_256_XTS (added in v1.55)
    const MEM_AES_256_XTS_BIT_22: u64 = 1u64 << 22;
    // Bit 23: RAPL_DIS (added in v1.55)
    const RAPL_DIS_BIT_23: u64 = 1u64 << 23;
    // Bit 24: CIPHERTEXT_HIDING (added in v1.55)
    const CIPHERTEXT_HIDING_BIT_24: u64 = 1u64 << 24;
    // Bit 25: PAGE_SWAP_DISABLE (added in v1.58)
    const PAGE_SWAP_DISABLE_BIT_25: u64 = 1u64 << 25;

    // Version constants
    const VERSION_1_55: FirmwareVersion = FirmwareVersion {
        major: 1,
        minor: 55,
        build: 0,
    };
    const VERSION_1_58: FirmwareVersion = FirmwareVersion {
        major: 1,
        minor: 58,
        build: 0,
    };

    fn validate_reserved_bits(self, version: FirmwareVersion) -> std::io::Result<()> {
        let raw = self.0;

        // bit 17 must be 1 (RMB1)
        if (raw & Self::RMB1_BIT_17) == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("GuestPolicy bit 17 must be 1 (raw=0x{raw:016x})"),
            ));
        }

        // bits 26..63 must be zero (MBZ)
        if (raw & Self::RESERVED_MBZ_MASK_26_63) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("GuestPolicy reserved bits 26..63 must be zero (raw=0x{raw:016x})"),
            ));
        }

        // bit 21 (CXL_ALLOW) is only defined for firmware v1.55+
        if version < Self::VERSION_1_55 && (raw & Self::CXL_ALLOW_BIT_21) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "GuestPolicy bit 21 (CXL_ALLOW) is only valid for firmware v1.55+ (raw=0x{raw:016x})"
                ),
            ));
        }

        // bit 22 (MEM_AES_256_XTS) is only defined for firmware v1.55+
        if version < Self::VERSION_1_55 && (raw & Self::MEM_AES_256_XTS_BIT_22) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "GuestPolicy bit 22 (MEM_AES_256_XTS) is only valid for firmware v1.55+ (raw=0x{raw:016x})"
                ),
            ));
        }

        // bit 23 (RAPL_DIS) is only defined for firmware v1.55+
        if version < Self::VERSION_1_55 && (raw & Self::RAPL_DIS_BIT_23) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "GuestPolicy bit 23 (RAPL_DIS) is only valid for firmware v1.55+ (raw=0x{raw:016x})"
                ),
            ));
        }

        // bit 24 (CIPHERTEXT_HIDING) is only defined for firmware v1.55+
        if version < Self::VERSION_1_55 && (raw & Self::CIPHERTEXT_HIDING_BIT_24) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "GuestPolicy bit 24 (CIPHERTEXT_HIDING) is only valid for firmware v1.55+ (raw=0x{raw:016x})"
                ),
            ));
        }

        // bit 25 (PAGE_SWAP_DISABLE) is only defined for firmware v1.58+
        if version < Self::VERSION_1_58 && (raw & Self::PAGE_SWAP_DISABLE_BIT_25) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "GuestPolicy bit 25 (PAGE_SWAP_DISABLE) is only valid for firmware v1.58+ (raw=0x{raw:016x})"
                ),
            ));
        }

        Ok(())
    }

    /// Formats the guest policy with version-aware display.
    ///
    /// Policy bits that are not defined for the given firmware version
    /// will be displayed as "None" instead of their actual value.
    ///
    /// # Arguments
    /// * `version` - The firmware version to use for determining which bits are valid
    ///
    /// # Returns
    /// A formatted string representation of the guest policy
    pub fn display_for_version(&self, version: FirmwareVersion) -> String {
        let cxl_allowed = if version >= Self::VERSION_1_55 {
            format!("{}", self.cxl_allowed())
        } else {
            "None".to_string()
        };

        let mem_aes_256_xts = if version >= Self::VERSION_1_55 {
            format!("{}", self.mem_aes_256_xts())
        } else {
            "None".to_string()
        };

        let rapl_dis = if version >= Self::VERSION_1_55 {
            format!("{}", self.rapl_dis())
        } else {
            "None".to_string()
        };

        let ciphertext_hiding = if version >= Self::VERSION_1_55 {
            format!("{}", self.ciphertext_hiding())
        } else {
            "None".to_string()
        };

        let page_swap_disabled = if version >= Self::VERSION_1_58 {
            format!("{}", self.page_swap_disabled())
        } else {
            "None".to_string()
        };

        format!(
            r#"Guest Policy (0x{:x}):
  ABI Major:         {}
  ABI Minor:         {}
  SMT Allowed:       {}
  Migrate MA:        {}
  Debug Allowed:     {}
  Single Socket:     {}
  CXL Allowed:       {}
  AES 256 XTS:       {}
  RAPL Disabled:     {}
  Ciphertext Hiding: {}
  Page Swap Disable: {}"#,
            self.0,
            self.abi_major(),
            self.abi_minor(),
            self.smt_allowed(),
            self.migrate_ma_allowed(),
            self.debug_allowed(),
            self.single_socket_required(),
            cxl_allowed,
            mem_aes_256_xts,
            rapl_dis,
            ciphertext_hiding,
            page_swap_disabled
        )
    }
}

impl Encoder<()> for GuestPolicy {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

// No checking in case policy is being parsed outside attestation report (e.g. id-block)
// Assumes latest version for all bits, since older firmware should ignore unknown bits and newer firmware should require reserved bits to be set to 1
impl Decoder<()> for GuestPolicy {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let policy = reader.read_bytes()?;
        Ok(Self(policy))
    }
}

// Checking reserved bytes according to known reserved bytes in attestation report
impl Decoder<FirmwareVersion> for GuestPolicy {
    fn decode(reader: &mut impl Read, version: FirmwareVersion) -> Result<Self, std::io::Error> {
        let raw: u64 = reader.read_bytes()?;
        let policy = GuestPolicy(raw);
        policy.validate_reserved_bits(version)?;
        Ok(policy)
    }
}

impl ByteParser<FirmwareVersion> for GuestPolicy {
    type Bytes = [u8; 8];
    const EXPECTED_LEN: Option<usize> = Some(8);
}

impl Display for GuestPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"Guest Policy (0x{:x}):
  ABI Major:     {}
  ABI Minor:     {}
  SMT Allowed:   {}
  Migrate MA:    {}
  Debug Allowed: {}
  Single Socket: {}
  CXL Allowed:   {}
  AEX 256 XTS:   {}
  RAPL Allowed:  {}
  Ciphertext hiding: {}
  Page Swap Disable: {}"#,
            self.0,
            self.abi_major(),
            self.abi_minor(),
            self.smt_allowed(),
            self.migrate_ma_allowed(),
            self.debug_allowed(),
            self.single_socket_required(),
            self.cxl_allowed(),
            self.mem_aes_256_xts(),
            self.rapl_dis(),
            self.ciphertext_hiding(),
            self.page_swap_disabled()
        )
    }
}

impl From<GuestPolicy> for u64 {
    fn from(value: GuestPolicy) -> Self {
        // Bit 17 of the guest policy is reserved and must always be set to 1.
        let reserved: u64 = 1 << 17;

        value.0 | reserved
    }
}

impl From<u64> for GuestPolicy {
    fn from(value: u64) -> Self {
        // Bit 17 of the guest policy is reserved and must always be set to 1.
        let reserved: u64 = 1 << 17;

        GuestPolicy(value | reserved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ByteParser;

    #[test]
    fn test_guest_policy_zeroed() {
        let gp: GuestPolicy = GuestPolicy(0);

        assert_eq!(gp.abi_minor(), 0);
        assert_eq!(gp.abi_major(), 0);
        assert!(!gp.smt_allowed());
        assert!(!gp.migrate_ma_allowed());
        assert!(!gp.debug_allowed());
        assert!(!gp.single_socket_required());
        assert!(!gp.cxl_allowed());
        assert!(!gp.mem_aes_256_xts());
        assert!(!gp.rapl_dis());
        assert!(!gp.ciphertext_hiding());
    }

    #[test]
    fn test_guest_policy_max() {
        let gp: GuestPolicy = GuestPolicy(0b1111111111111111111111111);

        assert_eq!(gp.abi_minor(), 0b11111111);
        assert_eq!(gp.abi_major(), 0b11111111);
        assert!(gp.smt_allowed());
        assert!(gp.migrate_ma_allowed());
        assert!(gp.debug_allowed());
        assert!(gp.single_socket_required());
        assert!(gp.cxl_allowed());
        assert!(gp.mem_aes_256_xts());
        assert!(gp.rapl_dis());
        assert!(gp.ciphertext_hiding());
    }

    #[test]
    fn test_set_guest_policy_max() {
        let mut gp: GuestPolicy = Default::default();

        assert_eq!(gp.abi_minor(), 0);
        gp.set_abi_minor(1);
        assert_eq!(gp.abi_minor(), 0b1);

        assert_eq!(gp.abi_major(), 0);
        gp.set_abi_major(1);
        assert_eq!(gp.abi_major(), 0b1);

        assert!(!gp.smt_allowed());
        gp.set_smt_allowed(true);
        assert!(gp.smt_allowed());

        assert!(!gp.migrate_ma_allowed());
        gp.set_migrate_ma_allowed(true);
        assert!(gp.migrate_ma_allowed());

        assert!(!gp.debug_allowed());
        gp.set_debug_allowed(true);
        assert!(gp.debug_allowed());

        assert!(!gp.single_socket_required());
        gp.set_single_socket_required(true);
        assert!(gp.single_socket_required());

        assert!(!gp.cxl_allowed());
        gp.set_cxl_allowed(true);
        assert!(gp.cxl_allowed());

        assert!(!gp.mem_aes_256_xts());
        gp.set_mem_aes_256_xts(true);
        assert!(gp.mem_aes_256_xts());

        assert!(!gp.rapl_dis());
        gp.set_rapl_dis(true);
        assert!(gp.rapl_dis());

        assert!(!gp.ciphertext_hiding());
        gp.set_ciphertext_hiding(true);
        assert!(gp.ciphertext_hiding());
    }

    #[test]
    fn test_guest_policy_from_u64() {
        let gp: GuestPolicy = GuestPolicy(5);

        // Bit 17 of the guest policy is reserved and must always be set to 1.
        let expected: u64 = (1 << 17) | 5;

        assert_eq!(u64::from(gp), expected);
    }
    #[test]
    fn test_guest_policy_serialization() {
        let mut original: GuestPolicy = GuestPolicy::from(0u64);
        original.set_abi_major(2);
        original.set_abi_minor(1);
        original.set_smt_allowed(true);
        original.set_debug_allowed(true);

        let buffer = original.to_bytes().unwrap();
        // Use a recent firmware version that supports all policy bits
        let decoded =
            GuestPolicy::from_bytes_with(&buffer, FirmwareVersion::new(1, 58, 0)).unwrap();
        assert_eq!(original, decoded);
    }
    #[test]
    fn test_guest_policy_combined_fields() {
        let mut policy: GuestPolicy = Default::default();

        policy.set_abi_major(2);
        policy.set_abi_minor(1);
        policy.set_smt_allowed(true);
        policy.set_debug_allowed(true);

        assert_eq!(policy.abi_major(), 2);
        assert_eq!(policy.abi_minor(), 1);
        assert!(policy.smt_allowed());
        assert!(policy.debug_allowed());

        let policy_u64: u64 = policy.into();
        assert_eq!(policy_u64 & (1 << 17), 1 << 17); // Reserved bit 17 must be 1
    }
}
