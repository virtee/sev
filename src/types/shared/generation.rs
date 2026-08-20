// SPDX-License-Identifier: Apache-2.0

//! EPYC processor generation identifiers and CPUID helpers.
//!
//! [`Generation`] drives TCB layout selection, built-in certificate chain
//! choice, and SNP platform ioctl decoding. On Linux x86_64 with the `snp`
//! feature, [`Generation::identify_host_generation`] reads host CPUID.

use std::convert::TryFrom;

/// A representation for EPYC generational product lines.
///
/// Implements type conversion traits to determine which generation
/// a given SEV certificate chain corresponds to. This is helpful for
/// automatically detecting what platform code is running on, as one
/// can simply export the SEV certificate chain and attempt to produce
/// a `Generation` from it with the [TryFrom](
/// https://doc.rust-lang.org/std/convert/trait.TryFrom.html) trait.
///
/// Host-side CPUID detection is available via [`Generation::identify_host_generation`]
/// on Linux x86_64 when the `snp` feature is enabled. Other targets must supply
/// [`Generation`] explicitly to platform and parsing APIs.
///
/// ## Example
///
/// ```no_run
/// use std::convert::TryFrom;
/// use sev::types::shared::Generation;
///
/// // Parse a generation name (available with `snp` and/or `sev` features).
/// let generation = Generation::try_from("milan".to_string()).unwrap();
/// assert_eq!(generation, Generation::Milan);
///
/// // Legacy SEV: infer generation from an exported platform certificate chain
/// // (`sev`, `crypto-openssl`, and `platform` features required).
/// # #[cfg(all(feature = "crypto-openssl", feature = "sev", feature = "platform"))]
/// # {
/// # use std::convert::TryFrom;
/// # use sev::platform::Firmware;
/// # let mut firmware = Firmware::open().unwrap();
/// # let chain = firmware.pdh_cert_export().unwrap();
/// # let generation = Generation::try_from(&chain).unwrap();
/// # let _ = generation.titlecase();
/// # }
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Generation {
    /// First generation EPYC (SEV).
    #[cfg(feature = "sev")]
    Naples,

    /// Second generation EPYC (SEV, SEV-ES).
    #[cfg(feature = "sev")]
    Rome,

    /// Third generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Milan,

    /// Fourth generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Genoa,

    /// Fifth generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Turin,

    /// Sixth generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Venice,
}

/// CPUID base/extended family byte used with [`Generation::identify_cpu`].
#[cfg(feature = "snp")]
pub type CpuFamily = u8;

/// CPUID model byte used with [`Generation::identify_cpu`].
#[cfg(feature = "snp")]
pub type CpuModel = u8;

#[cfg(feature = "snp")]
impl TryFrom<&[u8]> for Generation {
    type Error = std::io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid length of bytes representing cpuid",
            ));
        }

        let base_model = (bytes[0] & 0xF0) >> 4;
        let base_family = bytes[1] & 0x0F;

        let ext_model = bytes[2] & 0x0F;

        let ext_family = {
            let low = (bytes[2] & 0xF0) >> 4;
            let high = (bytes[3] & 0x0F) << 4;

            low | high
        };

        let family = base_family + ext_family;
        let model = (ext_model << 4) | base_model;

        Self::identify_cpu(family, model)
    }
}

#[cfg(feature = "snp")]
impl TryFrom<(CpuFamily, CpuModel)> for Generation {
    type Error = std::io::Error;

    fn try_from(val: (CpuFamily, CpuModel)) -> Result<Self, Self::Error> {
        Self::identify_cpu(val.0, val.1)
    }
}

#[cfg(feature = "snp")]
impl Generation {
    /// Identify the SEV generation based on the CPU family and model.
    pub fn identify_cpu(family: u8, model: u8) -> Result<Self, std::io::Error> {
        match family {
            0x19 => match model {
                0x0..=0xF => Ok(Self::Milan),
                0x10..=0x1F | 0xA0..=0xAF => Ok(Self::Genoa),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "processor is not of know SEV-SNP model.",
                )),
            },
            0x1A => match model {
                0x0..=0x11 => Ok(Self::Turin),
                0x50..=0x57 | 0x90..=0x9F | 0xA0..=0xAF | 0xC0..=0xC7 => Ok(Self::Venice),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "processor is not of know SEV-SNP model.",
                )),
            },
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "processor is not of know SEV-SNP generation.",
            )),
        }
    }

    /// Identify the local EPYC generation using CPUID.
    ///
    /// Only available when compiling for Linux x86_64 with the `snp` feature.
    /// Platform APIs such as [`crate::platform::Firmware::snp_platform_status`]
    /// take [`Generation`] explicitly; use this helper when running on the host and
    /// the generation is not already known.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub fn identify_host_generation() -> Result<Self, std::io::Error> {
        crate::firmware::cpuid::identify_host_generation()
    }
}

#[cfg(any(feature = "sev", feature = "snp"))]
impl TryFrom<String> for Generation {
    type Error = ();

    fn try_from(val: String) -> Result<Self, Self::Error> {
        match &val.to_lowercase()[..] {
            #[cfg(feature = "sev")]
            "naples" => Ok(Self::Naples),

            #[cfg(feature = "sev")]
            "rome" => Ok(Self::Rome),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "milan" => Ok(Self::Milan),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "genoa" => Ok(Self::Genoa),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "bergamo" => Ok(Self::Genoa),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "siena" => Ok(Self::Genoa),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "turin" => Ok(Self::Turin),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "venice" => Ok(Self::Venice),

            _ => Err(()),
        }
    }
}

#[cfg(any(feature = "sev", feature = "snp"))]
impl Generation {
    /// Create a title-cased string identifying the SEV generation.
    pub fn titlecase(&self) -> String {
        match self {
            #[cfg(feature = "sev")]
            Self::Naples => "Naples".to_string(),

            #[cfg(feature = "sev")]
            Self::Rome => "Rome".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Milan => "Milan".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Genoa => "Genoa".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Turin => "Turin".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Venice => "Venice".to_string(),
        }
    }
}
