// SPDX-License-Identifier: Apache-2.0

//! SNP ID block and ID authentication block wire types.
//!
//! The ID block binds a guest to an expected launch digest, family/image IDs,
//! guest policy, and SVN at launch. The ID authentication block carries ECDSA
//! P-384 signatures and public keys that authorize the ID block.
//!
//! Used by [`crate::attestation::reference::snp::idblock`] for launch digest
//! workflows and by [`crate::launch`] when submitting launch parameters.
//!
//! # Layout
//!
//! ```text
//!  IdBlock          — launch digest, IDs, policy, SVN (guest binding)
//!  IdAuth           — signatures + public keys authorizing the ID block
//!    └── ecdsa      — P-384 coordinate and signature wire layouts
//!    └── ids        — FamilyId, ImageId (128-bit owner identifiers)
//! ```
//!
//! # Constants
//!
//! Default values for ID block construction live at module scope
//! ([`DEFAULT_ID_VERSION`], [`DEFAULT_ID_POLICY`], etc.).

mod auth;
mod block;
mod ecdsa;
mod ids;

pub use auth::IdAuth;
pub use block::IdBlock;
pub use ecdsa::{SevEcdsaKeyData, SevEcdsaPubKey, SevEcdsaSig, ECDSA_POINT_SIZE_BYTES};
pub use ids::{FamilyId, ImageId};

/// Default ID block format version.
pub const DEFAULT_ID_VERSION: u32 = 1;

/// Default guest policy for ID blocks (`0x30000`).
pub const DEFAULT_ID_POLICY: u64 = 0x30000;

/// Default signing key algorithm identifier (ECDSA P-384).
pub const DEFAULT_KEY_ALGO: u32 = 1;

/// Curve identifier for P-384 keys in ID authentication blocks.
pub const CURVE_P384: u32 = 2;
