// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Failure while encoding or decoding bytes.
///
/// A short buffer, a wrong length, and a non-zero reserved region are their own
/// variants.
/// Reading a file or an ioctl buffer reports [`std::io::Error`] at that call,
/// before a [`crate::parser::Cursor`] is built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// A read asked for `needed` bytes and the buffer ended first.
    UnexpectedEof {
        /// Number of bytes this read requested.
        needed: usize,
    },
    /// `from_bytes` or `from_bytes_with` received a buffer of the wrong length.
    LengthMismatch {
        /// Length required by [`crate::parser::Decoder::LEN`].
        expected: usize,
        /// Length of the buffer that was passed in.
        actual: usize,
    },
    /// Encoding produced a byte buffer of the wrong length.
    EncodeLength {
        /// Length required by [`crate::parser::Decoder::LEN`].
        expected: usize,
        /// Length of the encoded buffer.
        actual: usize,
    },
    /// A reserved region contained a non-zero byte.
    ///
    /// `at` is the cursor position of the first byte of the region. The cursor
    /// is left on that byte.
    NonZeroReserved {
        /// Cursor position where the reserved region starts.
        at: usize,
        /// Length of the reserved region.
        len: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnexpectedEof { needed } => {
                write!(f, "unexpected end of input while reading {needed} bytes")
            }
            ParseError::LengthMismatch { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            ParseError::EncodeLength { expected, actual } => {
                write!(
                    f,
                    "encoded length {actual} does not match expected {expected}"
                )
            }
            ParseError::NonZeroReserved { at, len } => {
                write!(f, "non-zero reserved bytes at offset {at}, length {len}")
            }
        }
    }
}

impl std::error::Error for ParseError {}
