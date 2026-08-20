// SPDX-License-Identifier: Apache-2.0

//! SEV / SEV-ES launch digest reference value calculation.
//!
//! Wire types for OVMF parsing and VMSA construction live in
//! [`crate::types::shared::reference`].

mod measurement;

pub use measurement::*;
