// SPDX-License-Identifier: Apache-2.0

//! Provides access to "built-in" AMD SEV ARK and ASK certificates.
//!
//! These are primarily offered as a convenience measure to avoid making
//! HTTP requests to AMD's servers.

pub mod genoa;
pub mod milan;
pub mod naples;
pub mod rome;
