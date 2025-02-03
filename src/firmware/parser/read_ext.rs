// SPDX-License-Identifier: Apache-2.0
use super::byte_parser::ByteParser;
use std::io::Read;

pub(crate) trait ReadExt {
    fn parse_bytes<T, const SKIP: usize>(&mut self) -> Result<T, std::io::Error>
    where
        T: ByteParser<Bytes: AsMut<[u8]>>;
}

impl<R> ReadExt for R
where
    R: Read,
{
    #[inline(always)]
    fn parse_bytes<T, const SKIP: usize>(&mut self) -> Result<T, std::io::Error>
    where
        T: ByteParser<Bytes: AsMut<[u8]>>,
    {
        if SKIP != 0 {
            let mut skipped_bytes = [0; SKIP];
            self.read_exact(&mut skipped_bytes)?;

            if skipped_bytes != [0; SKIP] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Skipped bytes were expected to be zeroed.",
                ));
            }
        }

        let mut bytes = T::default().to_bytes();
        self.read_exact(bytes.as_mut())?;
        Ok(T::from_bytes(bytes))
    }
}

#[cfg(test)]
mod read_ext_tests {
    use super::*;
    use std::io::{self, Read};

    // Mock Reader implementation
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
        let result: Result<u32, _> = reader.parse_bytes::<u32, 0>();
        assert_eq!(result.unwrap(), 0x78563412);
    }

    // Test case 2: Skip, Valid Data
    #[test]
    fn test_skip_valid_data() {
        let data = vec![0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
        let mut reader = MockReader::new(data);
        let result: Result<u32, _> = reader.parse_bytes::<u32, 4>();
        assert_eq!(result.unwrap(), 0x78563412);
    }

    // Test case 3: Skip, Invalid Data
    #[test]
    fn test_skip_invalid_data() {
        let data = vec![0, 0, 1, 0, 0x12, 0x34, 0x56, 0x78];
        let mut reader = MockReader::new(data);
        let result: Result<u32, _> = reader.parse_bytes::<u32, 4>();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    // Test case 4: Read Fails (UnexpectedEof)
    #[test]
    fn test_read_fails() {
        let data = vec![0x12, 0x34];
        let mut reader = MockReader::new(data);
        let result: Result<u32, _> = reader.parse_bytes::<u32, 0>();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    // Test case 5: Zero Length Read
    #[test]
    fn test_zero_length_read() {
        let data: Vec<u8> = vec![];
        let mut reader = MockReader::new(data);
        let result: Result<[u8; 0], _> = reader.parse_bytes::<[u8; 0], 0>();
        assert!(result.is_ok());
    }

    // Test case 6: Empty Reader
    #[test]
    fn test_empty_reader() {
        let data: Vec<u8> = vec![];
        let mut reader = MockReader::new(data);
        let result: Result<u32, _> = reader.parse_bytes::<u32, 0>();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
