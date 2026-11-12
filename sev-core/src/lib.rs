// SPDX-License-Identifier: Apache-2.0

//! Traits and concepts shared by the SEV-SNP crates.

#![deny(clippy::all)]
#![deny(missing_docs)]
#![allow(clippy::unreadable_literal)]

pub mod attestable;
pub mod authenticate;
pub mod parser;
pub mod verifiable;

pub use attestable::Attestable;
pub use authenticate::Authenticate;
pub use verifiable::Verifiable;
