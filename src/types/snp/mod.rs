// SPDX-License-Identifier: Apache-2.0

//! SEV-SNP firmware ABI value types.
//!
//! Wire types for SNP attestation, guest launch, platform management, and
//! derived-key requests. Requires the `snp` feature.
//!
//! # Categories
//!
//! | Category | Types / modules | Typical consumers |
//! |----------|-----------------|-------------------|
//! | Endorsement | [`CertType`], [`CertTableEntry`] | [`crate::attestation::endorser::snp`], guest cert table |
//! | Attestation reports | [`GuestPolicy`], [`TcbVersion`] | [`crate::attestation::evidence::snp`] |
//! | Launch | [`IdBlock`], [`IdAuth`], [`SnpLaunchDigest`], [`PageType`] | [`crate::launch`], [`crate::attestation::reference::snp`] |
//! | Platform | [`platform`](self::platform), [`MaskId`](platform_config::MaskId) | [`crate::platform::snp`] |
//! | Guest keys | [`DerivedKey`](derived_key::DerivedKey), [`GuestFieldSelect`](derived_key::GuestFieldSelect) | [`crate::attestation::attester::snp`] |
//!
//! Offline reference-measurement wire types (OVMF, vCPU, VMSA) live in
//! [`crate::types::shared::reference`].
//!
//! # Parsing notes
//!
//! - Most types use [`ByteParser`](crate::parser::ByteParser) with `()` context.
//! - [`TcbVersion`] and types under [`platform`](self::platform) require
//!   [`Generation`](crate::types::shared::Generation).
//! - [`GuestPolicy`] reserved-bit validation is
//!   [`FirmwareVersion`](crate::types::shared::FirmwareVersion)-aware.
//!
//! # Terminology
//!
//! **Launch digest** and **expected measurement** refer to the same 48-byte
//! SHA-384 guest measurement ([`SnpLaunchDigest`]), stored in the ID block and
//! attestation report body.

mod cert;
mod cert_table;
mod derived_key;
mod id_block;
mod launch_digest;
mod page_type;
mod platform_config;
mod policy;
mod tcb;

pub use cert::CertType;
pub use cert_table::{CertTableEntry, RawData};
pub use derived_key::{DerivedKey, GuestFieldSelect};
pub use id_block::{
    FamilyId, IdAuth, IdBlock, ImageId, SevEcdsaKeyData, SevEcdsaPubKey, SevEcdsaSig, CURVE_P384,
    ECDSA_POINT_SIZE_BYTES,
};
pub use launch_digest::{SnpLaunchDigest, LD_BITS, LD_BYTES};
pub use page_type::PageType;
pub use platform_config::MaskId;
pub use policy::GuestPolicy;
pub use tcb::TcbVersion;

pub mod platform;
