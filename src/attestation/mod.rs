// SPDX-License-Identifier: Apache-2.0

//! RATS-oriented attestation types, production, verification, and reference
//! values.
//!
//! Enable individual role features (`evidence`, `verifier`, `endorser`,
//! `attester`, `reference`) to compile only the attestation surface you need.
//!
//! Offline launch digest wire types (OVMF, vCPU, VMSA) live in
//! [`crate::types::shared::reference`] and are shared by
//! [`crate::attestation::reference::snp`] and
//! [`crate::attestation::reference::sev`].
#[cfg(all(
    feature = "attester",
    target_os = "linux",
    any(feature = "sev", feature = "snp")
))]
pub mod attester;

#[cfg(all(feature = "evidence", any(feature = "sev", feature = "snp")))]
pub mod evidence;

#[cfg(all(
    feature = "endorser",
    any(
        all(
            feature = "snp",
            any(feature = "crypto-openssl", feature = "crypto-rust")
        ),
        all(feature = "sev", feature = "crypto-openssl")
    )
))]
pub mod endorser;

#[cfg(all(feature = "reference", any(feature = "sev", feature = "snp")))]
pub mod reference;

#[cfg(all(
    feature = "verifier",
    any(
        all(
            feature = "snp",
            any(feature = "crypto-openssl", feature = "crypto-rust")
        ),
        all(feature = "sev", feature = "crypto-openssl")
    )
))]
pub mod verifier;

#[cfg(all(
    feature = "verifier",
    any(
        all(
            feature = "snp",
            any(feature = "crypto-openssl", feature = "crypto-rust")
        ),
        all(feature = "sev", feature = "crypto-openssl")
    )
))]
pub use verifier::Verifiable;

#[cfg(all(feature = "evidence", feature = "snp"))]
pub use evidence::snp::{
    KeyInfo, PlatformInfo, Report, ReportBody, ReportVariant, Signature, SignatureAlgorithm,
};

#[cfg(all(feature = "evidence", feature = "sev", feature = "crypto-openssl"))]
pub use evidence::sev::LegacyAttestationReport;
