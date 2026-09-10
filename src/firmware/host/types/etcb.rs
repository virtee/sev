// SPDX-License-Identifier: Apache-2.0

//! Extended Trusted Computing Base (TCB) version.
//!
//! [`EtcbVersion`] is reported only by Venice parts. It is the 256-bit
//! `ETCB_VERSION` field: fourteen single-byte SVNs occupying bits 111:0, with
//! bits 255:112 reserved.
//!
//! Unlike [`TcbVersion`](super::TcbVersion), whose byte order changes between
//! EPYC generations, `ETCB_VERSION` has a single layout, so it encodes and
//! decodes with unit parameters rather than a
//! [`Generation`](crate::Generation).

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};

use std::{
    fmt::{self, Display},
    io::{Read, Write},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Size of the serialized `ETCB_VERSION` field, in bytes.
const ETCB_VERSION_LEN: usize = 32;

/// EtcbVersion represents the extended TCB version reported by Venice
/// parts.
///
/// (Table 6; Structure of the ETCB_VERSION Field for "Venice" based programs)
///
/// Each field is a one-byte SVN. Fields are listed here from the most
/// significant byte down, matching the order of the specification table; on the
/// wire the field is little-endian, so `ip_key_manager` (bits 7:0) is byte 0 and
/// `arg` (bits 111:104) is byte 13. Bits 255:112 are reserved.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct EtcbVersion {
    /// Bits 111:104. SVN of AMD Root Guest (ARG).
    pub arg: u8,
    /// Bits 103:96. DPE Driver (ASP) version; SVN of DPE Driver firmware.
    pub dpe_driver: u8,
    /// Bits 95:88. FHP Driver (ASP) version; SVN of FHP Driver firmware.
    pub fhp_driver: u8,
    /// Bits 87:80. ASP OS Driver version; SVN of ASP OS Driver firmware.
    pub asp_os_driver: u8,
    /// Bits 79:72. SoC Driver (ASP) firmware version; SVN of SoC Driver firmware.
    pub soc_driver: u8,
    /// Bits 71:64. Lowest current patch level of all cores; SPL (Security Patch
    /// Level) of all cores.
    pub microcode: u8,
    /// Bits 63:56. Current TMPM firmware version; SVN of TMPM firmware.
    pub tmpm: u8,
    /// Bits 55:48. Current PreEsid driver (ASP) firmware version; SVN of PreEsid
    /// driver firmware.
    pub pre_esid: u8,
    /// Bits 47:40. Current driver boot (ASP) firmware version; SVN of driver
    /// boot firmware.
    pub boot_driver: u8,
    /// Bits 39:32. Current High Availability and Debuggability (HAD) firmware
    /// version; SVN of HAD firmware.
    pub had_driver: u8,
    /// Bits 31:24. Current AMD Root of Trust (ART) version; SVN of ART runtime.
    pub art_rt: u8,
    /// Bits 23:16. Current ART FMC version; SVN of ART FMC.
    pub art_fmc: u8,
    /// Bits 15:8. Power Management firmware version; SVN of MP1 firmware.
    pub mp1: u8,
    /// Bits 7:0. Current IP Key Manager (ASP) firmware version; SVN of IP Key
    /// Manager firmware.
    pub ip_key_manager: u8,
}

impl EtcbVersion {
    pub(crate) fn from_venice_bytes(bytes: &[u8; ETCB_VERSION_LEN]) -> Self {
        Self {
            ip_key_manager: bytes[0],
            mp1: bytes[1],
            art_fmc: bytes[2],
            art_rt: bytes[3],
            had_driver: bytes[4],
            boot_driver: bytes[5],
            pre_esid: bytes[6],
            tmpm: bytes[7],
            microcode: bytes[8],
            soc_driver: bytes[9],
            asp_os_driver: bytes[10],
            fhp_driver: bytes[11],
            dpe_driver: bytes[12],
            arg: bytes[13],
        }
    }

    pub(crate) fn to_venice_bytes(self) -> [u8; ETCB_VERSION_LEN] {
        let mut bytes = [0u8; ETCB_VERSION_LEN];
        bytes[0] = self.ip_key_manager;
        bytes[1] = self.mp1;
        bytes[2] = self.art_fmc;
        bytes[3] = self.art_rt;
        bytes[4] = self.had_driver;
        bytes[5] = self.boot_driver;
        bytes[6] = self.pre_esid;
        bytes[7] = self.tmpm;
        bytes[8] = self.microcode;
        bytes[9] = self.soc_driver;
        bytes[10] = self.asp_os_driver;
        bytes[11] = self.fhp_driver;
        bytes[12] = self.dpe_driver;
        bytes[13] = self.arg;
        // Bytes 14..32 (bits 255:112) are reserved and left zeroed.
        bytes
    }
}

impl Encoder<()> for EtcbVersion {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.to_venice_bytes(), ())?;
        Ok(())
    }
}

impl Decoder<()> for EtcbVersion {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        Ok(EtcbVersion::from_venice_bytes(&reader.read_bytes()?))
    }
}

impl ByteParser<()> for EtcbVersion {
    type Bytes = [u8; ETCB_VERSION_LEN];
    const EXPECTED_LEN: Option<usize> = Some(ETCB_VERSION_LEN);
}

impl Display for EtcbVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"ETCB Version:
  ARG:            {}
  DPE Driver:     {}
  FHP Driver:     {}
  ASP OS Driver:  {}
  SoC Driver:     {}
  Microcode:      {}
  TMPM:           {}
  PreEsid:        {}
  Boot Driver:    {}
  HAD Driver:     {}
  ART RT:         {}
  ART FMC:        {}
  MP1:            {}
  IP Key Manager: {}"#,
            self.arg,
            self.dpe_driver,
            self.fhp_driver,
            self.asp_os_driver,
            self.soc_driver,
            self.microcode,
            self.tmpm,
            self.pre_esid,
            self.boot_driver,
            self.had_driver,
            self.art_rt,
            self.art_fmc,
            self.mp1,
            self.ip_key_manager,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes 0..14 hold the SVNs; bytes 14..32 are reserved.
    fn sample_bytes() -> [u8; ETCB_VERSION_LEN] {
        let mut bytes = [0u8; ETCB_VERSION_LEN];
        for (i, byte) in bytes.iter_mut().take(14).enumerate() {
            *byte = (i + 1) as u8;
        }
        bytes
    }

    fn sample_etcb() -> EtcbVersion {
        EtcbVersion {
            ip_key_manager: 1,
            mp1: 2,
            art_fmc: 3,
            art_rt: 4,
            had_driver: 5,
            boot_driver: 6,
            pre_esid: 7,
            tmpm: 8,
            microcode: 9,
            soc_driver: 10,
            asp_os_driver: 11,
            fhp_driver: 12,
            dpe_driver: 13,
            arg: 14,
        }
    }

    #[test]
    fn test_etcb_version_default() {
        let etcb = EtcbVersion::default();
        assert_eq!(etcb.arg, 0);
        assert_eq!(etcb.microcode, 0);
        assert_eq!(etcb.ip_key_manager, 0);
        assert_eq!(etcb.to_venice_bytes(), [0u8; ETCB_VERSION_LEN]);
    }

    #[test]
    fn test_etcb_version_copy() {
        let etcb = sample_etcb();
        let copy = etcb;
        assert_eq!(etcb, copy);
    }

    /// Each field must land on the byte its bit range implies.
    #[test]
    fn test_etcb_version_bit_positions() {
        let etcb = EtcbVersion::from_venice_bytes(&sample_bytes());
        assert_eq!(etcb, sample_etcb());
    }

    #[test]
    fn test_etcb_version_round_trip() {
        let bytes = sample_bytes();
        let etcb = EtcbVersion::from_venice_bytes(&bytes);
        assert_eq!(etcb.to_venice_bytes(), bytes);
    }

    /// Bits 255:112 are reserved: ignored when decoding, zeroed when encoding.
    #[test]
    fn test_etcb_version_reserved_bytes() {
        let mut bytes = sample_bytes();
        bytes[14..].fill(0xFF);

        let etcb = EtcbVersion::from_venice_bytes(&bytes);
        assert_eq!(etcb, sample_etcb());
        assert_eq!(etcb.to_venice_bytes()[14..], [0u8; 18]);
    }

    #[test]
    fn test_etcb_version_parse_and_write_bytes() {
        let bytes = sample_bytes();
        let etcb = EtcbVersion::from_bytes(&bytes).unwrap();
        assert_eq!(etcb, sample_etcb());
        assert_eq!(etcb.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn test_etcb_version_short_buffer() {
        assert!(EtcbVersion::from_bytes(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_etcb_version_display() {
        let expected = r#"ETCB Version:
  ARG:            14
  DPE Driver:     13
  FHP Driver:     12
  ASP OS Driver:  11
  SoC Driver:     10
  Microcode:      9
  TMPM:           8
  PreEsid:        7
  Boot Driver:    6
  HAD Driver:     5
  ART RT:         4
  ART FMC:        3
  MP1:            2
  IP Key Manager: 1"#;
        assert_eq!(expected, sample_etcb().to_string());
    }
}
