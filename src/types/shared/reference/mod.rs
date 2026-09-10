// SPDX-License-Identifier: Apache-2.0

//! Offline reference-measurement wire types for launch digest calculation.
//!
//! Shared by legacy SEV / SEV-ES and SNP reference measurement. These types
//! parse OVMF firmware images and build VMSA pages for
//! [`crate::attestation::reference`]. They are not used by the runtime
//! [`crate::launch`] ioctl path (which talks to the host kernel directly).
//!
//! Compiled with the `reference` feature because only the RATS Reference Value
//! Provider role consumes them. Wire parsing uses basic
//! [`crate::util::parser_helper`] `ReadExt` / `WriteExt` helpers; SNP-only
//! parser helpers require the `snp` feature separately.
//!
//! # Submodules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`ovmf`](self::ovmf) | OVMF SEV metadata sections and firmware image parser |
//! | [`vcpu`](self::vcpu) | QEMU vCPU model identifiers |
//! | [`vmsa`](self::vmsa) | SEV-ES / SNP VMSA page layout and builder |

pub mod ovmf;
pub mod vcpu;
pub mod vmsa;
