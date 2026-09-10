// SPDX-License-Identifier: Apache-2.0

//! [`Write`] extension methods for firmware wire encoding.
//!
//! Implemented for all [`Write`] types. Delegates to
//! [`Encoder::encode`](crate::parser::Encoder::encode) and provides zero-fill
//! padding for reserved struct fields.

use crate::parser::Encoder;
use std::io::Write;

/// Extension trait adding encode helpers to any [`Write`] sink.
pub trait WriteExt: Write {
    /// Encode a value using its [`Encoder`](crate::parser::Encoder) impl.
    ///
    /// Pass `()` for context-free types or a context value (such as
    /// [`Generation`](crate::types::shared::Generation)) when the wire layout
    /// depends on platform or firmware revision.
    fn write_bytes<T, P>(&mut self, value: T, params: P) -> Result<(), std::io::Error>
    where
        Self: Sized,
        T: Encoder<P>,
    {
        value.encode(self, params)
    }

    /// Write `SKIP` zero bytes for a reserved firmware field.
    ///
    /// Returns `self` for method chaining. A no-op when `SKIP` is `0`.
    fn skip_bytes<const SKIP: usize>(&mut self) -> Result<&mut Self, std::io::Error>
    where
        Self: Sized,
    {
        if SKIP != 0 {
            self.write_all(&[0; SKIP])?;
        }
        Ok(self)
    }
}

impl<W> WriteExt for W where W: Write {}

#[cfg(test)]
mod write_ext_tests {
    use super::*;

    // Mock writer to capture written bytes
    #[derive(Debug, Default)]
    struct MockWriter {
        written: Vec<u8>,
    }

    impl Write for MockWriter {
        fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    #[test]
    fn test_write_bytes_no_skip() -> Result<(), std::io::Error> {
        let mut writer = MockWriter::default();
        let value: u32 = 0x12345678;
        writer.write_bytes(value, ())?;

        assert_eq!(writer.written, [0x78, 0x56, 0x34, 0x12]);
        Ok(())
    }

    #[test]
    fn test_write_bytes_with_skip() -> Result<(), std::io::Error> {
        let mut writer = MockWriter::default();
        let value: u16 = 0xABCD;
        writer.skip_bytes::<2>()?.write_bytes(value, ())?;

        assert_eq!(writer.written, [0, 0, 0xCD, 0xAB]);
        Ok(())
    }

    #[test]
    fn test_mock_writer_flush() -> Result<(), std::io::Error> {
        let mut writer = MockWriter::default();
        writer.flush()?;
        // Flush doesn't modify the written buffer, so we just check that it executes without error.
        assert_eq!(writer.written.len(), 0);
        Ok(())
    }
}
