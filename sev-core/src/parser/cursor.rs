// SPDX-License-Identifier: Apache-2.0

use super::{Decoder, ParseError};

/// A position in a byte buffer.
///
/// The cursor borrows the caller's bytes. [`Cursor::take`] and
/// [`Cursor::skip_bytes_lax`] return slices of that same buffer. Copying a
/// cursor snapshots its position. Advancing the copy leaves the original in place.
#[derive(Clone, Copy, Debug)]
pub struct Cursor<'a> {
    full: &'a [u8],
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    /// Start at the first byte of `bytes`.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            full: bytes,
            rest: bytes,
        }
    }

    /// Bytes not yet consumed.
    pub const fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// `true` when [`Self::remaining`] is zero.
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Bytes not yet consumed, borrowed from the original buffer.
    pub const fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// Number of bytes already consumed.
    pub const fn position(&self) -> usize {
        self.full.len() - self.rest.len()
    }

    /// Split off the next `n` bytes.
    ///
    /// The cursor stays put when fewer than `n` bytes remain.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(ParseError::UnexpectedEof { needed: n })?;
        self.rest = tail;
        Ok(head)
    }

    /// Decode the next value.
    ///
    /// The type of the returned value selects the [`Decoder`] implementation,
    /// the same way `reader.read_bytes()?` did. A field assignment is enough
    /// for Rust to infer it.
    ///
    /// ```
    /// # use sev_core::parser::Cursor;
    /// let raw = [0x34, 0x12];
    /// let mut input = Cursor::new(&raw);
    /// let version: u16 = input.read_bytes().unwrap();
    /// assert_eq!(version, 0x1234);
    /// ```
    pub fn read_bytes<T>(&mut self) -> Result<T, T::Error>
    where
        T: Decoder<()>,
    {
        T::decode(self, ())
    }

    /// [`read_bytes`](Self::read_bytes) with parameters, such as a CPU generation.
    pub fn read_bytes_with<T, P>(&mut self, params: P) -> Result<T, T::Error>
    where
        T: Decoder<P>,
    {
        T::decode(self, params)
    }

    /// Skip `n` bytes that must each be zero.
    ///
    /// The cursor stays put when the buffer is short or any byte is non-zero.
    /// On success the same cursor is returned, so a skip can be followed by
    /// [`read_bytes`](Self::read_bytes).
    pub fn skip_bytes(&mut self, n: usize) -> Result<&mut Self, ParseError> {
        let region = self
            .rest
            .get(..n)
            .ok_or(ParseError::UnexpectedEof { needed: n })?;
        if region.iter().any(|byte| *byte != 0) {
            return Err(ParseError::NonZeroReserved {
                at: self.position(),
                len: n,
            });
        }
        self.rest = &self.rest[n..];
        Ok(self)
    }

    /// Skip `n` bytes and return the original region, including non-zero bytes.
    ///
    /// The cursor stays put when the buffer is short.
    pub fn skip_bytes_lax(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_advances_and_borrows_the_original_buffer() {
        let data = [1u8, 2, 3, 4, 5];
        let mut input = Cursor::new(&data);

        assert_eq!(input.position(), 0);
        assert_eq!(input.take(2).unwrap(), &[1, 2]);
        assert_eq!(input.position(), 2);
        assert_eq!(input.rest(), &[3, 4, 5]);
        assert!(!input.is_empty());
    }

    #[test]
    fn take_leaves_the_cursor_put_when_short() {
        let data = [1u8, 2];
        let mut input = Cursor::new(&data);

        assert_eq!(
            input.take(3).unwrap_err(),
            ParseError::UnexpectedEof { needed: 3 }
        );
        assert_eq!(input.position(), 0);
        assert_eq!(input.rest(), &data);
    }

    #[test]
    fn copy_snapshots_the_position() {
        let data = [1u8, 2, 3, 4];
        let mut input = Cursor::new(&data);
        input.take(1).unwrap();
        let saved = input;

        input.take(2).unwrap();
        assert_eq!(saved.rest(), &[2, 3, 4]);
        assert_eq!(input.rest(), &[4]);
    }

    #[test]
    fn skip_bytes_requires_zeros() {
        let data = [0u8, 0, 0, 9];
        let mut input = Cursor::new(&data);

        input.skip_bytes(3).unwrap();
        assert_eq!(input.rest(), &[9]);
    }

    #[test]
    fn skip_bytes_reports_nonzero_without_advancing() {
        let data = [0u8, 1, 0];
        let mut input = Cursor::new(&data);

        assert_eq!(
            input.skip_bytes(3).unwrap_err(),
            ParseError::NonZeroReserved { at: 0, len: 3 }
        );
        assert_eq!(input.position(), 0);
        assert_eq!(input.rest(), &data);
    }

    #[test]
    fn skip_bytes_lax_returns_the_original_region() {
        let data = [0u8, 1, 0, 4];
        let mut input = Cursor::new(&data);

        assert_eq!(input.skip_bytes_lax(3).unwrap(), &[0, 1, 0]);
        assert_eq!(input.rest(), &[4]);
    }
}
