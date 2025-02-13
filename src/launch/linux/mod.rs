// SPDX-License-Identifier: Apache-2.0

//! Operations and types for launching on Linux
pub(crate) mod ioctl;

#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
#[cfg(feature = "sev")]
pub(crate) mod sev;

#[cfg(feature = "snp")]
pub(crate) mod snp;

#[cfg(any(feature = "sev", feature = "snp"))]
pub(crate) mod shared;
