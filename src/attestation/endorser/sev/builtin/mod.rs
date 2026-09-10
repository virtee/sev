// SPDX-License-Identifier: Apache-2.0

//! Built-in AMD SEV ARK and ASK certificates by EPYC generation.
//!
//! These public trust anchors support legacy SEV workflows such as
//! [`ca::Chain`](super::ca::Chain) construction from
//! [`Generation`](crate::types::shared::Generation) and platform generation
//! inference in [`cert::Chain`](super::cert::Chain). SNP attestation does not use
//! this module; supply endorsement material from guest evidence or external
//! files instead.

pub mod genoa;
pub mod milan;
pub mod naples;
pub mod rome;
pub mod turin;
