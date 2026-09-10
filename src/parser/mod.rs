// SPDX-License-Identifier: Apache-2.0

//! Encoding and decoding traits for firmware ABI wire types.
//!
//! This module provides a layered serialization API for converting between Rust
//! values and the little-endian byte layouts defined by AMD SEV/SNP firmware and
//! the Linux kernel UAPI. Most wire types under [`crate::types`] implement one
//! or more of these traits.
//!
//! # Trait layers
//!
//! ```text
//!  ByteParser<P>          whole-buffer convenience (from_bytes / to_bytes)
//!       │                        │
//!       ├──── Decoder<P>  ◄──────┘  field-by-field read from a stream
//!       └──── Encoder<P>            field-by-field write to a stream
//! ```
//!
//! | Trait | Use when |
//! |-------|----------|
//! | [`Decoder`] | Reading the next field(s) from a sub-slice or stream |
//! | [`Encoder`] | Writing fields into a growing buffer or writer |
//! | [`ByteParser`] | Parsing or producing a complete fixed-size struct from/to a byte array |
//!
//! # Parameter type `P`
//!
//! Many layouts are context-dependent. The type parameter carries that context:
//!
//! - `()` — layout is fixed (for example [`FirmwareVersion`](crate::types::shared::FirmwareVersion))
//! - [`Generation`](crate::types::shared::Generation) — field sizes changed between EPYC generations (for example [`TcbVersion`](crate::types::snp::TcbVersion))
//! - [`FirmwareVersion`](crate::types::shared::FirmwareVersion) — reserved-bit validation depends on firmware rev (for example [`GuestPolicy`](crate::types::snp::GuestPolicy))
//!
//! Use [`ByteParser::from_bytes_with`] / [`ByteParser::to_bytes_with`] when `P` is
//! not `()`. The parameterless helpers [`ByteParser::from_bytes`] /
//! [`ByteParser::to_bytes`] require `Decoder<()>` / `Encoder<()>`.
//!
//! # Typical usage
//!
//! ```ignore
//! use sev::parser::ByteParser;
//! use sev::types::shared::{FirmwareVersion, Generation};
//! use sev::types::snp::{GuestPolicy, TcbVersion};
//!
//! // Fixed layout — no context parameter.
//! let version = FirmwareVersion::from_bytes(&buf)?;
//!
//! // Generation-dependent layout — pass explicit generation.
//! let tcb = TcbVersion::from_bytes_with(&buf, Generation::Turin)?;
//!
//! // Firmware-version-dependent layout.
//! let policy = GuestPolicy::from_bytes_with(&buf, fw_version)?;
//! ```
//!
//! For nested structs, implement [`Decoder`] / [`Encoder`] and compose by calling
//! `decode` / `encode` on sub-fields in order. [`ByteParser`] can then be
//! implemented as a thin wrapper or derived automatically when the full struct
//! maps to a fixed buffer.
//!
//! # Endianness and primitives
//!
//! Built-in impls for integers use **little-endian** byte order, matching AMD
//! firmware wire formats. Fixed-size `[u8; N]` arrays read/write raw bytes;
//! [`Vec<u8>`] reads to end-of-stream on decode.
//!
//! # Submodules
//!
//! | Module | Trait |
//! |--------|-------|
//! | [`encoder`](self::encoder) | [`Encoder`] |
//! | [`decoder`](self::decoder) | [`Decoder`] |
//! | [`byte_parser`](self::byte_parser) | [`ByteParser`] |

mod byte_parser;

mod encoder;

mod decoder;

pub use byte_parser::ByteParser;

pub use decoder::Decoder;

pub use encoder::Encoder;
