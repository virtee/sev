// SPDX-License-Identifier: Apache-2.0

//! Byte encoding and decoding over an in-memory buffer.
//!
//! Load a file or an ioctl buffer first, then walk it with [`Cursor`]. [`Decoder`]
//! and [`Encoder`] are what a struct uses to read and write its fields.
//! [`ByteParser`] is what a caller uses when the buffer is one complete value.
//!
//! # Examples
//!
//! A fixed layout implements both traits. Reserved bytes are skipped on decode
//! and written back as zeros on encode. Callers use [`ByteParser`] and do not
//! build a cursor. Little-endian integers match the SNP ABI.
//!
//! ```
//! use sev_core::parser::{ByteParser, ByteWrite, Cursor, Decoder, Encoder, ParseError};
//!
//! struct Header {
//!     version: u16,
//!     id: [u8; 4],
//! }
//!
//! impl Decoder<()> for Header {
//!     type Error = ParseError;
//!     const LEN: Option<usize> = Some(8);
//!
//!     fn decode(input: &mut Cursor<'_>, _params: ()) -> Result<Self, Self::Error> {
//!         let version = input.read_bytes()?;
//!         input.skip_bytes(2)?;
//!         let id = input.read_bytes()?;
//!         Ok(Self { version, id })
//!     }
//! }
//!
//! impl Encoder<()> for Header {
//!     type Error = ParseError;
//!
//!     fn encode(&self, output: &mut Vec<u8>, _params: ()) -> Result<(), Self::Error> {
//!         output.write_bytes(&self.version, ())?;
//!         output.skip_bytes(2);
//!         output.write_bytes(&self.id, ())?;
//!         Ok(())
//!     }
//! }
//!
//! let raw = [0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
//! let header = Header::from_bytes(&raw).unwrap();
//! assert_eq!(header.version, 2);
//! assert_eq!(header.id, [0xAA, 0xBB, 0xCC, 0xDD]);
//! assert_eq!(header.to_bytes().unwrap(), raw);
//! ```

mod byte_parser;
mod cursor;
mod decoder;
mod encoder;
mod error;

pub use byte_parser::ByteParser;
pub use cursor::Cursor;
pub use decoder::Decoder;
pub use encoder::{ByteWrite, Encoder};
pub use error::ParseError;
