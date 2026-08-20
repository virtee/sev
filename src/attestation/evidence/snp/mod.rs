// SPDX-License-Identifier: Apache-2.0

//! SEV-SNP attestation report evidence.
//!
//! [`Report`] is the top-level attestation report. [`ReportBody`] and the
//! [`fields`](self::fields) submodule expose parsed report sections for
//! verification and display.

mod body;
mod fields;
mod report;
mod signature;

pub use body::ReportBody;
pub use fields::{KeyInfo, PlatformInfo, ReportVariant};
pub use report::Report;
pub use signature::{Signature, SignatureAlgorithm};
