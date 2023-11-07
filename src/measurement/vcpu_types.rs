// SPDX-License-Identifier: Apache-2.0

//! Exisiting AMD EPYC vCPUs
use std::{convert::TryFrom, fmt, str::FromStr};

use crate::error::MeasurementError;

/// All currently available QEMU vCPU types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CpuType {
    /// EPYC
    Epyc,
    /// EPYC V1
    EpycV1,
    /// EPYC V2
    EpycV2,
    /// EPYC Indirect Branch Predictor Barrier
    EpycIBPB,
    /// EPYC V3
    EpycV3,
    /// EPYC V4
    EpycV4,
    /// EPYC ROME
    EpycRome,
    /// EPYC ROME V1
    EpycRomeV1,
    /// EPYC ROME V2
    EpycRomeV2,
    /// EPYC ROME V3
    EpycRomeV3,
    /// EPYC MILAN
    EpycMilan,
    /// EPYC MILAN V1
    EpycMilanV1,
    /// EPYC MILAN V2
    EpycMilanV2,
    /// EPYC GENOA
    EpycGenoa,
    /// EPYC GENOA V1
    EpycGenoaV1,
}

impl TryFrom<u8> for CpuType {
    type Error = MeasurementError;

    fn try_from(value: u8) -> Result<Self, MeasurementError> {
        match value {
            0 => Ok(CpuType::Epyc),
            1 => Ok(CpuType::EpycV1),
            3 => Ok(CpuType::EpycIBPB),
            4 => Ok(CpuType::EpycV3),
            5 => Ok(CpuType::EpycV4),
            6 => Ok(CpuType::EpycRome),
            7 => Ok(CpuType::EpycRomeV1),
            8 => Ok(CpuType::EpycRomeV2),
            9 => Ok(CpuType::EpycRomeV3),
            10 => Ok(CpuType::EpycMilan),
            11 => Ok(CpuType::EpycMilanV1),
            12 => Ok(CpuType::EpycMilanV2),
            13 => Ok(CpuType::EpycGenoa),
            14 => Ok(CpuType::EpycGenoaV1),
            _ => Err(MeasurementError::InvalidVcpuTypeError(value.to_string())),
        }
    }
}

impl CpuType {
    /// Matching CPU-Type with its CPU signature
    pub fn sig(&self) -> i32 {
        match self {
            CpuType::Epyc => cpu_sig(23, 1, 2),
            CpuType::EpycV1 => cpu_sig(23, 1, 2),
            CpuType::EpycV2 => cpu_sig(23, 1, 2),
            CpuType::EpycIBPB => cpu_sig(23, 1, 2),
            CpuType::EpycV3 => cpu_sig(23, 1, 2),
            CpuType::EpycV4 => cpu_sig(23, 1, 2),
            CpuType::EpycRome => cpu_sig(23, 49, 0),
            CpuType::EpycRomeV1 => cpu_sig(23, 49, 0),
            CpuType::EpycRomeV2 => cpu_sig(23, 49, 0),
            CpuType::EpycRomeV3 => cpu_sig(23, 49, 0),
            CpuType::EpycMilan => cpu_sig(25, 1, 1),
            CpuType::EpycMilanV1 => cpu_sig(25, 1, 1),
            CpuType::EpycMilanV2 => cpu_sig(25, 1, 1),
            CpuType::EpycGenoa => cpu_sig(25, 17, 0),
            CpuType::EpycGenoaV1 => cpu_sig(25, 17, 0),
        }
    }
}

impl fmt::Display for CpuType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CpuType::Epyc => write!(f, "EPYC"),
            CpuType::EpycV1 => write!(f, "EPYC-v1"),
            CpuType::EpycV2 => write!(f, "EPYC-v2"),
            CpuType::EpycIBPB => write!(f, "EPYC-IBPB"),
            CpuType::EpycV3 => write!(f, "EPYC-v3"),
            CpuType::EpycV4 => write!(f, "EPYC-v4"),
            CpuType::EpycRome => write!(f, "EPYC-Rome"),
            CpuType::EpycRomeV1 => write!(f, "EPYC-Rome-v1"),
            CpuType::EpycRomeV2 => write!(f, "EPYC-Rome-v2"),
            CpuType::EpycRomeV3 => write!(f, "EPYC-Rome-v3"),
            CpuType::EpycMilan => write!(f, "EPYC-Milan"),
            CpuType::EpycMilanV1 => write!(f, "EPYC-Milan-v1"),
            CpuType::EpycMilanV2 => write!(f, "EPYC-Milan-v2"),
            CpuType::EpycGenoa => write!(f, "EPYC-Genoa"),
            CpuType::EpycGenoaV1 => write!(f, "EPYC-Genoa-v1"),
        }
    }
}

impl FromStr for CpuType {
    type Err = MeasurementError;

    fn from_str(s: &str) -> Result<Self, MeasurementError> {
        match s.to_lowercase().as_str() {
            "epyc" => Ok(CpuType::Epyc),
            "epyc-v1" => Ok(CpuType::EpycV1),
            "epyc-v2" => Ok(CpuType::EpycV2),
            "epyc-ibpb" => Ok(CpuType::EpycIBPB),
            "epyc-v3" => Ok(CpuType::EpycV3),
            "epyc-v4" => Ok(CpuType::EpycV4),
            "epyc-rome" => Ok(CpuType::EpycRome),
            "epyc-rome-v1" => Ok(CpuType::EpycRomeV1),
            "epyc-rome-v2" => Ok(CpuType::EpycRomeV2),
            "epyc-rome-v3" => Ok(CpuType::EpycRomeV3),
            "epyc-milan" => Ok(CpuType::EpycMilan),
            "epyc-milan-v1" => Ok(CpuType::EpycMilanV1),
            "epyc-milan-v2" => Ok(CpuType::EpycMilanV2),
            "epyc-genoa" => Ok(CpuType::EpycGenoa),
            "epyc-genoa-v1" => Ok(CpuType::EpycGenoaV1),
            _ => Err(MeasurementError::InvalidVcpuTypeError(s.to_string())),
        }
    }
}

/// Compute the 32-bit CPUID signature from family, model, and stepping.
///
/// This computation is described in AMD's CPUID Specification, publication #25481
/// https://www.amd.com/system/files/TechDocs/25481.pdf
/// See section: CPUID Fn0000_0001_EAX Family, Model, Stepping Identifiers
pub fn cpu_sig(family: i32, model: i32, stepping: i32) -> i32 {
    let family_low;
    let family_high;

    if family > 0xf {
        family_low = 0xf;
        family_high = (family - 0x0f) & 0xff;
    } else {
        family_low = family;
        family_high = 0;
    }

    let model_low = model & 0xf;
    let model_high = (model >> 4) & 0xf;

    let stepping_low = stepping & 0xf;

    (family_high << 20) | (model_high << 16) | (family_low << 8) | (model_low << 4) | stepping_low
}
