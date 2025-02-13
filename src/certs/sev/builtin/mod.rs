// SPDX-License-Identifier: Apache-2.0

//! Provides access to "built-in" AMD SEV ARK and ASK certificates.
//!
//! These are primarily offered as a convenience measure to avoid making
//! HTTP requests to AMD's servers.
#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
pub mod genoa;
#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
pub mod milan;
#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
pub mod naples;
#[deprecated(
    since = "5.0.0",
    note = "Legacy SEV features will no longer be included/supported in library versions past 5"
)]
pub mod rome;
pub mod turin;
