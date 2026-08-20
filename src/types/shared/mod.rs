// SPDX-License-Identifier: Apache-2.0

//! ABI types shared across first-generation SEV and SEV-SNP.
//!
//! Cross-generation concepts that appear in both legacy SEV and SNP code paths.
//!
//! # Modules
//!
//! | Module | Types | Role |
//! |--------|-------|------|
//! | [`generation`](self::generation) | [`Generation`], [`CpuFamily`](Generation), [`CpuModel`](Generation) | EPYC product line; selects TCB layout and built-in cert chains |
//! | [`version`](self::version) | [`FirmwareVersion`] | Major/minor/build triple (wire parsing with `snp` only) |
//! | [`reference`](self::reference) | OVMF, vCPU, VMSA types | Offline launch digest wire types (`reference` feature) |
//!
//! # Generation parameter
//!
//! [`Generation`] is passed explicitly to SNP platform and parsing APIs when
//! wire layout depends on CPU generation. It is **not** inferred automatically
//! except via optional helpers such as
//! [`Generation::identify_host_generation`](Generation::identify_host_generation).

pub mod generation;
#[cfg(all(feature = "reference", any(feature = "sev", feature = "snp")))]
pub mod reference;
pub mod version;

pub use generation::Generation;
pub use version::FirmwareVersion;

#[cfg(feature = "snp")]
pub use generation::{CpuFamily, CpuModel};
