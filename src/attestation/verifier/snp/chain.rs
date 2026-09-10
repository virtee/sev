// SPDX-License-Identifier: Apache-2.0

//! AMD SNP certificate chain verification.
//!
//! Validates the endorsement hierarchy from the AMD root through the per-chip
//! VCEK or VLEK. Chain material is defined in
//! [`crate::attestation::endorser::snp`].
//!
//! # Chain shapes
//!
//! - [`CaChain`](crate::attestation::endorser::snp::CaChain): ARK + ASK only.
//!   Verification confirms the root is self-signed and endorses the platform
//!   signing key.
//! - [`Chain`](crate::attestation::endorser::snp::Chain): CA pair plus VCEK/VLEK.
//!   Verification walks the full path and returns the trusted endorsement key
//!   used to sign attestation reports.

use crate::attestation::endorser::snp::{ca::CaChain, Certificate, Chain};
use crate::attestation::verifier::Verifiable;

use std::io::Result;

/// Verify an AMD CA certificate pair (ARK + ASK).
///
/// Checks that:
/// 1. ARK is self-signed (`ARK` signs `ARK`).
/// 2. ARK signs ASK.
///
/// On success, returns a reference to the validated ASK.
impl<'a> Verifiable for &'a CaChain {
    type Output = &'a Certificate;

    fn verify(self) -> Result<Self::Output> {
        // Verify that ARK is self-signed.
        (&self.ark, &self.ark).verify()?;

        // Verify that ARK signs ASK.
        (&self.ark, &self.ask).verify()?;

        Ok(&self.ask)
    }
}

/// Verify a full SNP endorsement chain (ARK → ASK → VCEK/VLEK).
///
/// Checks that:
/// 1. The CA pair ([`CaChain`]) is valid (ARK self-signed, ARK signs ASK).
/// 2. ASK signs the VCEK or VLEK.
///
/// On success, returns a reference to the validated VCEK/VLEK — the key that
/// signs attestation reports for this chip or launch.
impl<'a> Verifiable for &'a Chain {
    type Output = &'a Certificate;

    fn verify(self) -> Result<Self::Output> {
        // Verify that ARK is self-signed and ARK signs ASK.
        let ask = self.ca.verify()?;

        // Verify that ASK signs VCEK.
        (ask, &self.vek).verify()?;

        Ok(&self.vek)
    }
}
