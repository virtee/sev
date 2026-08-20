// SPDX-License-Identifier: Apache-2.0

//! SNP guest derived-key request types.
//!
//! High-level parameters for the `SNP_GET_DERIVED_KEY` guest ioctl. Converted
//! into C layouts in [`crate::firmware::guest::types`] before submission to
//! `/dev/sev-guest`.
//!
//! Public API: [`crate::attestation::attester::snp::Firmware::get_derived_key`].
//!
//! # Submodules
//!
//! | Module | Type |
//! |--------|------|
//! | [`key`](self::key) | [`DerivedKey`] — root key, VMPL, SVN, TCB, field select |
//! | [`field_select`](self::field_select) | [`GuestFieldSelect`] — bitmask of guest fields mixed into the key |

mod field_select;
mod key;

pub use field_select::GuestFieldSelect;
pub use key::DerivedKey;
