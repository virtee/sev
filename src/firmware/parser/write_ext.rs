// SPDX-License-Identifier: Apache-2.0
use super::ByteParser;
use std::io::Write;

pub(crate) trait WriteExt {
    fn write_bytes<T: ByteParser, const SKIP: usize>(
        &mut self,
        value: T,
    ) -> Result<(), std::io::Error>;
}
impl<W> WriteExt for W
where
    W: Write,
{
    #[inline(always)]
    fn write_bytes<T: ByteParser, const SKIP: usize>(
        &mut self,
        value: T,
    ) -> Result<(), std::io::Error> {
        if SKIP != 0 {
            self.write_all(&[0; SKIP])?;
        }

        self.write_all(value.to_bytes().as_ref())
    }
}

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
        writer.write_bytes::<_, 0>(value)?;

        assert_eq!(writer.written, [0x78, 0x56, 0x34, 0x12]);
        Ok(())
    }

    #[test]
    fn test_write_bytes_with_skip() -> Result<(), std::io::Error> {
        let mut writer = MockWriter::default();
        let value: u16 = 0xABCD;
        writer.write_bytes::<_, 2>(value)?;

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
