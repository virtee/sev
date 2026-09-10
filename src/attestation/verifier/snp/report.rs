// SPDX-License-Identifier: Apache-2.0

//! High-level attestation report verification.
//!
//! Combines chain or VEK validation with report signature checks, and provides
//! the recommended path to a verified [`ReportBody`](crate::attestation::evidence::snp::ReportBody).
//!
//! # Usage
//!
//! Prefer `(&Chain, &Report).verify()` when you have a full endorsement chain.
//! Use `(&Certificate, &Report).verify()` when you already hold a trusted VEK.
//!
//! After verification succeeds, use [`ReportBody::try_from`] to parse typed
//! report fields without repeating the signature check.

use crate::attestation::endorser::snp::{Certificate, Chain};
use crate::attestation::evidence::snp::{Report, ReportBody};
use crate::attestation::verifier::Verifiable;

/// Verify an attestation report signature using a trusted VEK certificate.
///
/// Dispatches on `report.algorithm` and checks that `report.body` was signed by
/// the holder of `vek`'s private key. Does not validate the certificate itself —
/// `vek` must already be trusted (for example, after chain verification).
impl Verifiable for (&Certificate, &Report<'_>) {
    type Output = ();

    fn verify(self) -> Result<Self::Output, std::io::Error> {
        let (vek, report) = self;

        let algo = report.algorithm;

        (algo, report.body, report.signature, vek).verify()
    }
}

/// Verify an attestation report using a full endorsement chain.
///
/// Validates the chain (ARK → ASK → VCEK/VLEK), then verifies the report
/// signature with the resulting VEK. This is the typical entry point when
/// certificate material arrives alongside the report (for example, from an
/// extended guest report).
impl Verifiable for (&Chain, &Report<'_>) {
    type Output = ();

    fn verify(self) -> Result<(), std::io::Error> {
        let (chain, report) = self;
        let vek = chain.verify()?;
        (vek, report).verify()
    }
}

impl<'a> std::convert::TryFrom<(&Report<'a>, &Certificate)> for ReportBody<'a> {
    type Error = std::io::Error;

    /// Verify `report` with `vek`, then return a parsed [`ReportBody`].
    ///
    /// Runs signature verification before decoding body fields. Fails if the
    /// signature does not match or body parsing fails.
    fn try_from((report, vek): (&Report<'a>, &Certificate)) -> Result<Self, Self::Error> {
        (vek, report).verify()?;
        ReportBody::from_bytes(report.body)
    }
}

impl<'a> std::convert::TryFrom<(&Report<'a>, &Chain)> for ReportBody<'a> {
    type Error = std::io::Error;

    /// Verify `report` with `chain`, then return a parsed [`ReportBody`].
    ///
    /// This is the **recommended** way to obtain a [`ReportBody`]: chain
    /// validation and report signature verification run before any typed field
    /// access.
    fn try_from((report, chain): (&Report<'a>, &Chain)) -> Result<Self, Self::Error> {
        (chain, report).verify()?;
        ReportBody::from_bytes(report.body)
    }
}
