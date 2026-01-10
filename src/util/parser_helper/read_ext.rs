// SPDX-License-Identifier: Apache-2.0
// use super::byte_parser::ByteParser;
use crate::parser::Decoder;
use std::io::Read;

pub trait ReadExt: Read {
    /// Convenience: read a value with unit params.
    fn read_bytes<T>(&mut self) -> Result<T, std::io::Error>
    where
        Self: Sized,
        T: Decoder<()>,
    {
        T::decode(self, ())
    }

    /// Full version with explicit params.
    fn read_bytes_with<T, P>(&mut self, params: P) -> Result<T, std::io::Error>
    where
        Self: Sized,
        T: Decoder<P>,
    {
        T::decode(self, params)
    }

    /// Read SKIP bytes and verify they are zero; returns a mutable reference to the same reader.
    fn skip_bytes<const SKIP: usize>(&mut self) -> Result<&mut Self, std::io::Error> {
        if SKIP != 0 {
            // Read in chunks to avoid huge stack allocations for large SKIP.
            const CHUNK: usize = 256;
            let mut buf = [0u8; CHUNK];
            let mut remaining = SKIP;

            while remaining > 0 {
                let n = remaining.min(CHUNK);
                self.read_exact(&mut buf[..n])?;
                if buf[..n].iter().any(|&b| b != 0) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Skipped bytes were expected to be zeroed.",
                    ));
                }
                remaining -= n;
            }
        }
        Ok(self)
    }

    #[cfg(not(feature = "lax-parser"))]
    /// Read N bytes and verify they are zero.
    fn read_reserved_bytes<const N: usize>(&mut self) -> Result<[u8; N], std::io::Error>
    where
        Self: Sized,
    {
        self.skip_bytes::<N>()?;
        Ok([0; N])
    }

    #[cfg(feature = "lax-parser")]
    /// Read N bytes.
    fn read_reserved_bytes<const N: usize>(&mut self) -> Result<[u8; N], std::io::Error>
    where
        Self: Sized,
    {
        <[u8; N]>::decode(self, ())
    }
}

impl<R> ReadExt for R where R: Read {}

#[cfg(test)]
mod read_ext_tests {
    use super::*;
    use std::io::{self, Read};

    // Mock Reader implementation
    #[derive(Debug)]
    struct MockReader {
        data: Vec<u8>,
        position: usize,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader { data, position: 0 }
        }
    }

    impl Read for MockReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = std::cmp::min(buf.len(), self.data.len() - self.position);
            if len > 0 {
                buf[..len].copy_from_slice(&self.data[self.position..self.position + len]);
                self.position += len;
                Ok(len)
            } else {
                Ok(0) // Indicate EOF
            }
        }
    }

    // Test case 1: No Skip, Valid Data
    #[test]
    fn test_no_skip_valid_data() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let mut reader = MockReader::new(data);
        let result: Result<u32, _> = reader.read_bytes();
        assert_eq!(result.unwrap(), 0x78563412);
    }

    // Test case 2: Skip, Valid Data
    #[test]
    fn test_skip_valid_data() {
        let data = vec![0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
        let mut reader = MockReader::new(data);
        let result: Result<u32, _> = reader.skip_bytes::<4>().unwrap().read_bytes();
        assert_eq!(result.unwrap(), 0x78563412);
    }

    // Test case 3: Skip, Invalid Data
    #[test]
    fn test_skip_invalid_data() {
        let data = vec![0, 0, 1, 0, 0x12, 0x34, 0x56, 0x78];
        let mut reader = MockReader::new(data);
        let result = reader.skip_bytes::<4>();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    // Test case 4: Read Fails (UnexpectedEof)
    #[test]
    fn test_read_fails() {
        let data = vec![0x12, 0x34];
        let mut reader = MockReader::new(data);
        let result: Result<u32, _> = reader.read_bytes();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    // Test case 5: Zero Length Read
    #[test]
    fn test_zero_length_read() {
        let data: Vec<u8> = vec![];
        let mut reader = MockReader::new(data);
        let result: Result<[u8; 0], _> = reader.read_bytes();
        assert!(result.is_ok());
    }

    // Test case 6: Empty Reader
    #[test]
    fn test_empty_reader() {
        let data: Vec<u8> = vec![];
        let mut reader = MockReader::new(data);
        let result: Result<u32, _> = reader.read_bytes();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
