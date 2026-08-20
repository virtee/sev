// SPDX-License-Identifier: Apache-2.0

//! SNP platform status, configuration, and certificate-table types.
//!
//! These structures mirror the SNP firmware platform ABI (Chapter 8). Decode
//! with [`ByteParser::from_bytes_with`](crate::parser::ByteParser::from_bytes_with)
//! and an explicit [`Generation`](crate::types::shared::Generation).
//! Host ioctl wrappers that populate them live in [`crate::platform::snp`].

pub use super::cert_table::{CertTableEntry, RawData};

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    types::shared::Generation,
    util::{
        hexline::HexLine,
        parser_helper::{ReadExt, WriteExt},
    },
};
use std::{
    fmt::Display,
    io::{Read, Write},
    ops::BitOrAssign,
};

use bitfield::bitfield;

pub use super::{CertType, MaskId, TcbVersion};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

bitfield! {
    /// The platform's status flags.
    #[derive(Default)]
    pub struct SnpPlatformStatusFlags(u32);
    impl Debug;

    /// If set, this platform is owned. Otherwise, it is self-owned.
    pub is_owned, _: 0;

    /// If set, encrypted state functionality is present.
    pub is_encrypted_state_present, _: 8;
}

impl BitOrAssign for SnpPlatformStatusFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

bitfield! {
    /// Various platform initialization configuration data. Byte 0x3 in SEV-SNP's
    /// STRUCT_PLATFORM_STATUS.
    #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    pub struct PlatformInit(u8);
    impl Debug;

    /// Indicates if RMP is initialized.
    pub is_rmp_init, _: 0;

    /// Indicates that alias detection has completed since the last system reset
    /// and there are no aliasing addresses. Resets to 0.
    /// Added in firmware version:
    ///     Milan family: 1.55.22
    ///     Genoa family: 1.55.38
    pub alias_check_complete, _: 1;

    /// Indicates TIO is enabled. Present if SevTio feature bit is set.
    pub is_tio_en, _: 3;
}

impl Encoder<()> for PlatformInit {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

impl Decoder<()> for PlatformInit {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let init = reader.read_bytes()?;
        Ok(Self(init))
    }
}

impl ByteParser<()> for PlatformInit {
    type Bytes = [u8; 1];
    const EXPECTED_LEN: Option<usize> = Some(1);
}

impl BitOrAssign for PlatformInit {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Query the SEV-SNP platform status.
///
/// (Chapter 8.3; Table 38)
#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct SnpPlatformStatus {
    /// The firmware API version (major.minor)
    pub version: (u8, u8),

    /// The platform state.
    pub state: u8,

    /// RMP initialization and platform readiness flags (firmware byte 0x3).
    pub is_rmp_init: PlatformInit,

    /// The platform build ID.
    pub build_id: u32,

    /// Platform policy flags (mask chip ID/key, VLEK loaded, RAPL, …).
    pub platform_policy: PlatformPolicy,

    /// The number of valid guests maintained by the SEV-SNP firmware.
    pub guest_count: u32,

    /// Installed TCB version.
    pub platform_tcb_version: TcbVersion,

    /// Reported TCB version.
    pub reported_tcb_version: TcbVersion,
}

impl Encoder<Generation> for SnpPlatformStatus {
    fn encode(
        &self,
        writer: &mut impl Write,
        generation: Generation,
    ) -> Result<(), std::io::Error> {
        writer.write_bytes(self.version.0, ())?;
        writer.write_bytes(self.version.1, ())?;
        writer.write_bytes(self.is_rmp_init, ())?;
        writer.write_bytes(self.build_id, ())?;
        writer.write_bytes(self.platform_policy, ())?;
        writer.write_bytes(self.guest_count, ())?;
        writer.write_bytes(self.platform_tcb_version, generation)?;
        writer.write_bytes(self.reported_tcb_version, generation)?;
        Ok(())
    }
}

impl Decoder<Generation> for SnpPlatformStatus {
    fn decode(reader: &mut impl Read, generation: Generation) -> Result<Self, std::io::Error> {
        let major = reader.read_bytes()?;
        let minor = reader.read_bytes()?;
        Ok(Self {
            version: (major, minor),
            state: reader.read_bytes()?,
            is_rmp_init: reader.read_bytes()?,
            build_id: reader.read_bytes()?,
            platform_policy: reader.read_bytes()?,
            guest_count: reader.read_bytes()?,
            platform_tcb_version: reader.read_bytes_with(generation)?,
            reported_tcb_version: reader.read_bytes_with(generation)?,
        })
    }
}

impl ByteParser<Generation> for SnpPlatformStatus {
    type Bytes = [u8; 32];
    const EXPECTED_LEN: Option<usize> = Some(32);
}

/// SNP platform-wide configuration written by [`crate::platform::Firmware::snp_set_config`].
///
/// Controls the reported TCB version embedded in guest attestation reports and
/// whether the chip ID field is masked via [`MaskId`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Config {
    /// The TCB_VERSION to report in guest attestation reports.
    pub reported_tcb: TcbVersion,

    /// Indicates that the CHIP_ID field in the attestation report will always
    /// be zero.
    pub mask_id: MaskId,

    /// Reserved. Must be zero.
    reserved: [u8; 52],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            reported_tcb: Default::default(),
            mask_id: Default::default(),
            reserved: [0; 52],
        }
    }
}

impl Config {
    /// Creates platform configuration with the given reported TCB and mask ID.
    pub fn new(reported_tcb: TcbVersion, mask_id: MaskId) -> Self {
        Self {
            reported_tcb,
            mask_id,
            reserved: [0; 52],
        }
    }
}

bitfield! {
    /// Policy settings that appear in SNP PLATFORM STATUS
    ///
    /// | Bit(s) | Name | Description |
    /// |--------|------|-------------|
    /// |0|MASK_CHIP_ID|Set to the value of MaskChipID.|
    /// |1|MASK_CHIP_KEY|Set to the value of MaskChipKey.|
    /// |2|VLEK_EN|Indicates whether a VLEK hashtick is loaded|
    /// |3|FEATURE_INFO|Indicates that the SNP_FEATURE_INFO command is available.|
    /// |4|RAPL_DIS|Indicates that the RAPL is disabled.|
    /// |5|CIPHERTEXT_HIDING_DRAM_CAP|Indicates platform capable of ciphertext hiding for the DRAM.|
    /// |6|CIPHERTEXT_HIDING_DRAM_EN|Indicates ciphertext hiding is enabled for the DRAM.|
    /// |31:7|-|Reserved.|
    #[repr(C)]
    #[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PlatformPolicy(u32);
    impl Debug;
    /// Indicates that the CHIP_ID field in the attestation report will alwaysbe zero.
    pub mask_chip_id, _: 0;
    /// Indicates that the VCEK is not used in attestation and guest key derivation.
    pub mask_chip_key, _: 1;
    /// Indicates whether a VLEK hashtick is loaded
    pub vlek_en, _: 2;
    /// Indicates that the SNP_FEATURE_INFO command is available.
    pub feature_info, _: 3;
    /// Indicates that the RAPL is disabled.
    pub rapl_dis, _: 4;
    /// Indicates platform capable of ciphertext hiding for the DRAM.
    pub ciphertext_hiding_dram_cap, _: 5;
    /// Indicates ciphertext hiding is enabled for the DRAM.
    pub ciphertext_hiding_dram_en, _: 6;
    /// Indicates TIO is enbaled. Present if SEV-TIO feature bit is set.
    pub is_tio_en, _: 7;
}

impl Encoder<()> for PlatformPolicy {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

impl Decoder<()> for PlatformPolicy {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let policy = reader.read_bytes()?;
        Ok(Self(policy))
    }
}

impl ByteParser<()> for PlatformPolicy {
    type Bytes = [u8; 4];
    const EXPECTED_LEN: Option<usize> = Some(4);
}

impl Display for PlatformPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
    MaskID ({}):
    Mask Chip ID Enabled: {}
    Mask Chip Key Enabled: {}
    Vlek Enabled: {}
    Feature Info Enabled {}
    RAPL Disabled: {}
    Ciphertext Capable: {}
    Ciphertext enabled: {}
    SEV-TIO enabled: {}"#,
            self.0,
            self.mask_chip_id(),
            self.mask_chip_key(),
            self.vlek_en(),
            self.feature_info(),
            self.rapl_dis(),
            self.ciphertext_hiding_dram_cap(),
            self.ciphertext_hiding_dram_en(),
            self.is_tio_en()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Wrapped VLEK hashstick passed to [`crate::platform::Firmware::snp_vlek_load`].
///
/// Defined in AMD SEV-SNP firmware specification Chapter 8.30. The structure is
/// AES-256-GCM wrapped and includes the associated TCB version.
pub struct WrappedVlekHashstick {
    /// IV used to wrap chip-unique key
    pub iv: [u8; 12], // 96 bits = 12 bytes

    // Reserved [u8;4]
    /// VLEK hashstick wrapped with a chip-unique key using AES-256-GCM
    pub vlek_wrapped: [u8; 384],

    /// The TCB version associated with this VLEK hashstick
    pub tcb_version: TcbVersion,

    // Reserved [u8;8]
    /// AES-256-GCM authentication tag of the wrapped VLEK hashstick and TCB_VERSION
    pub vlek_auth_tag: [u8; 16],
}

impl Default for WrappedVlekHashstick {
    fn default() -> Self {
        Self {
            iv: Default::default(),
            vlek_wrapped: [0u8; 384],
            tcb_version: Default::default(),
            vlek_auth_tag: Default::default(),
        }
    }
}

impl Encoder<Generation> for WrappedVlekHashstick {
    fn encode(
        &self,
        writer: &mut impl Write,
        generation: Generation,
    ) -> Result<(), std::io::Error> {
        writer.write_bytes(self.iv, ())?;
        // Reserved [u8;4]
        writer
            .skip_bytes::<4>()?
            .write_bytes(self.vlek_wrapped, ())?;
        writer.write_bytes(self.tcb_version, generation)?;
        // Reserved [u8;8]
        writer
            .skip_bytes::<8>()?
            .write_bytes(self.vlek_auth_tag, ())?;
        Ok(())
    }
}

impl Decoder<Generation> for WrappedVlekHashstick {
    fn decode(reader: &mut impl Read, generation: Generation) -> Result<Self, std::io::Error> {
        let iv = reader.read_bytes()?;
        let vlek_wrapped = reader.skip_bytes::<4>()?.read_bytes()?;
        let tcb_version = reader.read_bytes_with(generation)?;
        let vlek_auth_tag = reader.skip_bytes::<8>()?.read_bytes()?;
        Ok(Self {
            iv,
            vlek_wrapped,
            tcb_version,
            vlek_auth_tag,
        })
    }
}

impl ByteParser<Generation> for WrappedVlekHashstick {
    type Bytes = [u8; 432];
    const EXPECTED_LEN: Option<usize> = Some(432);
}

impl Display for WrappedVlekHashstick {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"
    Wrapped VLEK Hashstick:
    IV:                      {}
    VLEK hashstic Wrapped:   {}
    TCB: 
    {}
    VLEK authentication tag: {}"#,
            HexLine(&self.iv),
            HexLine(&self.vlek_wrapped),
            self.tcb_version,
            HexLine(&self.vlek_auth_tag)
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg(all(feature = "platform", feature = "snp"))]
    use crate::firmware::host::types::SnpSetConfig;

    #[cfg(all(feature = "platform", feature = "snp"))]
    use std::convert::TryInto;

    #[cfg(feature = "platform")]
    use crate::firmware::host::types::SnpPlatformStatus as FfiSnpPlatformStatus;

    #[test]
    fn test_snp_platform_status_flags_zeroed() {
        let actual: SnpPlatformStatusFlags = SnpPlatformStatusFlags(0);

        assert!(!actual.is_owned());
        assert!(!actual.is_encrypted_state_present());
    }

    #[test]
    fn test_snp_platform_status_flags_full() {
        let mut actual: SnpPlatformStatusFlags = SnpPlatformStatusFlags(0);

        actual.0 |= 1;
        actual.0 |= 1 << 8;
        assert!(actual.is_owned());
        assert!(actual.is_encrypted_state_present());
    }

    #[test]
    #[cfg(all(feature = "platform", feature = "snp"))]
    fn test_config() {
        let tcb = TcbVersion::new(None, 1, 2, 3, 4);
        let mask = MaskId(0x3);
        let config = Config::new(tcb, mask);

        assert_eq!(config.reported_tcb, tcb);
        let config_mask = config.mask_id;
        assert_eq!(config_mask, mask);

        // Test conversion to FFI type
        let snp_config: SnpSetConfig = (config, Generation::Milan).try_into().unwrap();
        assert_eq!(snp_config.reported_tcb, tcb.to_legacy_bytes());
        let snp_config_mask = snp_config.mask_id;

        assert_eq!(snp_config_mask, mask);
    }

    // Test PlatformInit flags
    #[test]
    fn test_platform_init() {
        let mut init = PlatformInit(0);

        assert!(!init.is_rmp_init());
        init.0 |= 1;
        assert!(init.is_rmp_init());

        assert!(!init.alias_check_complete());
        init.0 |= 1 << 1;
        assert!(init.alias_check_complete());

        assert!(!init.is_tio_en());
        init.0 |= 1 << 3;
        assert!(init.is_tio_en());
    }

    // Test MaskId bitfield operations
    #[test]
    fn test_platform_status() {
        let status = SnpPlatformStatus::default();
        assert_eq!(status.state, 0);
        assert_eq!(status.guest_count, 0);

        let init_status = SnpPlatformStatus {
            is_rmp_init: PlatformInit(1),
            ..Default::default()
        };
        assert!(init_status.is_rmp_init.is_rmp_init());
    }

    // MaskId Tests
    #[test]
    #[cfg(all(feature = "platform", feature = "snp"))]
    fn test_config_conversions() {
        let tcb = TcbVersion::new(None, 1, 2, 3, 4);
        let mask = MaskId(0x3);
        let config = Config::new(tcb, mask);

        let ffi_config: SnpSetConfig = (config, Generation::Milan).try_into().unwrap();
        assert_eq!(ffi_config.reported_tcb, tcb.to_legacy_bytes());
        let ffi_config_mask = ffi_config.mask_id;
        assert_eq!(ffi_config_mask, mask);

        let converted_config: Config = (ffi_config, Generation::Milan).try_into().unwrap();
        assert_eq!(converted_config.reported_tcb, tcb);
        let converted_config_mask = converted_config.mask_id;
        assert_eq!(converted_config_mask, mask);
    }

    // SnpPlatformStatus Tests
    #[test]
    fn test_platform_status_initialization() {
        let mut status = SnpPlatformStatus::default();
        assert_eq!(status.state, 0);
        assert_eq!(status.guest_count, 0);

        status.is_rmp_init = PlatformInit(1);
        assert!(status.is_rmp_init.is_rmp_init());

        status.platform_tcb_version = TcbVersion::new(None, 1, 2, 3, 4);
        assert_eq!(status.platform_tcb_version.snp, 3);
    }

    #[test]
    #[cfg(all(feature = "platform", feature = "snp"))]
    fn test_config_error_cases() {
        let tcb = TcbVersion::new(None, 255, 255, 255, 255);
        let mask = MaskId(u32::MAX);
        let config = Config::new(tcb, mask);

        let ffi_result: Result<SnpSetConfig, _> = (config, Generation::Milan).try_into();
        assert!(ffi_result.is_ok());

        let default_config = Config::default();
        assert_eq!(default_config.reported_tcb, Default::default());
        let default_config_mask_id = default_config.mask_id;
        assert_eq!(default_config_mask_id, Default::default());
    }

    #[test]
    #[cfg(all(feature = "platform", feature = "snp"))]
    fn test_config_edge_cases() {
        // Test with maximum values
        let tcb = TcbVersion::new(Some(255), 255, 255, 255, 255);
        let mask_id = MaskId(u32::MAX);
        let config = Config::new(tcb, mask_id);

        // Convert to SnpSetConfig
        let result: Result<SnpSetConfig, _> = (config, Generation::Turin).try_into();
        assert!(result.is_ok());
        let snp_config = result.unwrap();

        // Convert back to Config
        let result: Result<Config, _> = (snp_config, Generation::Turin).try_into();
        assert!(result.is_ok());
        let round_trip = result.unwrap();

        assert_eq!(round_trip.reported_tcb, tcb);
        let round_trip_mask_id = round_trip.mask_id;
        assert_eq!(round_trip_mask_id, mask_id);

        // Test with minimum values
        let tcb = TcbVersion::new(Some(0), 0, 0, 0, 0);
        let mask_id = MaskId(0);
        let config = Config::new(tcb, mask_id);

        // Convert to SnpSetConfig
        let result: Result<SnpSetConfig, _> = (config, Generation::Turin).try_into();
        assert!(result.is_ok());
        let snp_config = result.unwrap();

        // Convert back to Config
        let result: Result<Config, _> = (snp_config, Generation::Turin).try_into();
        assert!(result.is_ok());
        let round_trip = result.unwrap();

        assert_eq!(round_trip.reported_tcb, tcb);
        let round_trip_mask_id = round_trip.mask_id;
        assert_eq!(round_trip_mask_id, mask_id);
    }

    #[test]
    #[cfg(all(feature = "platform", feature = "snp"))]
    fn test_different_generation_conversions() {
        let tcb = TcbVersion::new(Some(1), 2, 3, 4, 5);
        let mask_id = MaskId(0x3);
        let config = Config::new(tcb, mask_id);

        // Test all generations
        let generations = [
            Generation::Milan,
            Generation::Genoa,
            Generation::Turin,
            Generation::Venice,
        ];

        for generation in generations {
            // Convert to SnpSetConfig
            let snp_config: Result<SnpSetConfig, _> = (config, generation).try_into();
            assert!(snp_config.is_ok());
            let snp_config = snp_config.unwrap();

            // Convert back to Config
            let round_trip: Result<Config, _> = (snp_config, generation).try_into();
            assert!(round_trip.is_ok());
            let round_trip = round_trip.unwrap();

            // For non-Turin generations, FMC will be lost in the conversion
            match generation {
                Generation::Turin | Generation::Venice => assert_eq!(round_trip.reported_tcb, tcb),
                _ => {
                    // FMC field is not preserved for legacy generations
                    assert_eq!(round_trip.reported_tcb.bootloader, tcb.bootloader);
                    assert_eq!(round_trip.reported_tcb.tee, tcb.tee);
                    assert_eq!(round_trip.reported_tcb.snp, tcb.snp);
                    assert_eq!(round_trip.reported_tcb.microcode, tcb.microcode);
                    assert_eq!(round_trip.reported_tcb.fmc, None); // FMC lost in legacy format
                }
            }
            let round_trip_mask_id = round_trip.mask_id;
            assert_eq!(round_trip_mask_id, mask_id);
        }
    }

    #[test]
    fn test_platform_status_boundary() {
        let status = SnpPlatformStatus {
            guest_count: u32::MAX,
            build_id: u32::MAX,
            platform_policy: PlatformPolicy(u32::MAX),
            ..Default::default()
        };

        assert_eq!(status.guest_count, u32::MAX);
        assert_eq!(status.build_id, u32::MAX);
    }

    #[test]
    fn test_config_reserved() {
        let config = Config::default();
        assert_eq!(config.reserved, [0u8; 52]);
    }

    #[test]
    fn test_platform_status_all_fields() {
        let status: SnpPlatformStatus = SnpPlatformStatus {
            version: (1, 2),
            build_id: 0xDEADBEEF,
            platform_policy: PlatformPolicy(0x7f),
            state: 0xFF,
            ..Default::default()
        };
        assert_eq!(status.version.0, 1);
        assert_eq!(status.version.1, 2);
        assert_eq!(status.build_id, 0xDEADBEEF);
        assert!(status.platform_policy.mask_chip_id());
        assert!(status.platform_policy.mask_chip_key());
        assert!(status.platform_policy.vlek_en());
        assert!(status.platform_policy.feature_info());
        assert!(status.platform_policy.rapl_dis());
        assert!(status.platform_policy.ciphertext_hiding_dram_cap());
        assert!(status.platform_policy.ciphertext_hiding_dram_en());
        assert_eq!(status.state, 0xFF);
    }

    #[test]
    fn test_snp_platform_status_flags_bitor_assign() {
        let mut flags1 = SnpPlatformStatusFlags::default();
        let flags2 = SnpPlatformStatusFlags::default();
        flags1 |= flags2;
        assert_eq!(flags1.0, 0);

        let mut flags1 = SnpPlatformStatusFlags(1);
        let flags2 = SnpPlatformStatusFlags(2);
        flags1 |= flags2;
        assert_eq!(flags1.0, 3);
    }

    #[test]
    fn test_platform_init_bitor_assign() {
        let mut init1: PlatformInit = Default::default();
        let init2: PlatformInit = Default::default();
        init1 |= init2;
        assert_eq!(init1.0, 0);

        let mut init1 = PlatformInit(1);
        let init2 = PlatformInit(2);
        init1 |= init2;
        assert_eq!(init1.0, 3);
    }

    #[test]
    #[cfg(feature = "platform")]
    fn test_snp_platform_status_non_turin() {
        let expected: SnpPlatformStatus = SnpPlatformStatus {
            version: (1, 1),
            state: 1,
            is_rmp_init: PlatformInit(1),
            build_id: 1,
            platform_policy: PlatformPolicy(1),
            guest_count: 0,
            platform_tcb_version: TcbVersion {
                fmc: None,
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
            reported_tcb_version: TcbVersion {
                fmc: None,
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
        };
        let raw_actual: FfiSnpPlatformStatus = FfiSnpPlatformStatus {
            buffer: [
                1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, // Other stuff
                1, 1, 0, 0, 0, 0, 1, 1, //Platform TCB
                1, 1, 0, 0, 0, 0, 1, 1, //Reported TCB
            ],
        };
        let actual =
            SnpPlatformStatus::from_bytes_with(&raw_actual.buffer, Generation::Milan).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    #[cfg(feature = "platform")]
    fn test_snp_platform_status_turin() {
        let expected: SnpPlatformStatus = SnpPlatformStatus {
            version: (1, 1),
            state: 1,
            is_rmp_init: PlatformInit(1),
            build_id: 1,
            platform_policy: PlatformPolicy(1),
            guest_count: 0,
            platform_tcb_version: TcbVersion {
                fmc: Some(1),
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
            reported_tcb_version: TcbVersion {
                fmc: Some(1),
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
        };
        let raw_actual: FfiSnpPlatformStatus = FfiSnpPlatformStatus {
            buffer: [
                1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, // Other stuff
                1, 1, 1, 1, 0, 0, 0, 1, //Platform TCB
                1, 1, 1, 1, 0, 0, 0, 1, //Reported TCB
            ],
        };
        let actual =
            SnpPlatformStatus::from_bytes_with(&raw_actual.buffer, Generation::Turin).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_wrapped_vlek_hashstick_from_bytes() {
        // Create a test buffer with the correct layout
        let mut test_buffer = Vec::with_capacity(432);

        // IV (12 bytes)
        test_buffer.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        // Reserved field 1 (4 bytes of zeros)
        test_buffer.extend_from_slice(&[0, 0, 0, 0]);

        // VLEK_WRAPPED (384 bytes)
        test_buffer.extend_from_slice(&[42; 384]);

        // TCB_VERSION (8 bytes)
        test_buffer.extend_from_slice(&[1, 2, 0, 0, 0, 0, 3, 4]); // bootloader=1, tee=2, snp=3, microcode=4

        // Reserved field 2 (8 bytes of zeros)
        test_buffer.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

        // VLEK_AUTH_TAG (16 bytes)
        test_buffer.extend_from_slice(&[9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0]);

        // Parse the buffer
        let hashstick =
            WrappedVlekHashstick::from_bytes_with(test_buffer.as_slice(), Generation::Milan)
                .unwrap();

        // Verify the fields
        assert_eq!(hashstick.iv, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(hashstick.vlek_wrapped.as_ref(), &[42; 384]);
        assert_eq!(hashstick.tcb_version.bootloader, 1);
        assert_eq!(hashstick.tcb_version.tee, 2);
        assert_eq!(hashstick.tcb_version.snp, 3);
        assert_eq!(hashstick.tcb_version.microcode, 4);
        assert_eq!(
            hashstick.vlek_auth_tag,
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_wrapped_vlek_hashstick_to_bytes() {
        // Create a test hashstick
        let hashstick = WrappedVlekHashstick {
            iv: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vlek_wrapped: [42; 384],
            tcb_version: TcbVersion::new(None, 1, 2, 3, 4),
            vlek_auth_tag: [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0],
        };

        let buffer = hashstick.to_bytes_with(Generation::Milan).unwrap();

        // Verify the buffer is the correct length
        assert_eq!(buffer.len(), 432);

        // Verify the fields were written correctly
        assert_eq!(&buffer[0..12], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]); // IV
        assert_eq!(&buffer[0x0C..0x10], &[0, 0, 0, 0]); // Reserved field 1
        assert_eq!(&buffer[0x10..0x190], &[42; 384]); // VLEK_WRAPPED

        // TCB_VERSION format depends on the CPU generation, so we'll read it back
        let tcb_bytes = &buffer[0x190..0x198];

        let tcb = TcbVersion::from_bytes_with(tcb_bytes, Generation::Milan).unwrap();
        assert_eq!(tcb.bootloader, 1);
        assert_eq!(tcb.tee, 2);
        assert_eq!(tcb.snp, 3);
        assert_eq!(tcb.microcode, 4);

        assert_eq!(&buffer[0x198..0x1A0], &[0, 0, 0, 0, 0, 0, 0, 0]); // Reserved field 2
        assert_eq!(
            &buffer[0x1A0..0x1B0],
            &[9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0]
        ); // VLEK_AUTH_TAG
    }

    #[test]
    fn test_wrapped_vlek_hashstick_invalid_length() {
        // Test with a buffer that's too short
        let test_buffer = [0u8; 431]; // One byte too short
        let result = WrappedVlekHashstick::from_bytes_with(&test_buffer, Generation::Milan);
        assert!(result.is_err());

        // Test with a buffer that's too long
        let test_buffer = [0u8; 433]; // One byte too long
        let result = WrappedVlekHashstick::from_bytes_with(&test_buffer, Generation::Milan);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrapped_vlek_hashstick_display() {
        // Create a test hashstick
        let hashstick = WrappedVlekHashstick {
            iv: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            vlek_wrapped: [42; 384],
            tcb_version: TcbVersion::new(None, 1, 2, 3, 4),
            vlek_auth_tag: [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0],
        };

        // Convert to string and check contents
        let display_string = format!("{}", hashstick);
        assert!(display_string.contains("Wrapped VLEK Hashstick:"));
        assert!(display_string.contains("IV:"));
        assert!(display_string.contains("VLEK hashstic Wrapped:"));
        assert!(display_string.contains("TCB:"));
        assert!(display_string.contains("VLEK authentication tag:"));
    }
}
