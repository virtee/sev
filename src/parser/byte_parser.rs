// SPDX-License-Identifier: Apache-2.0

use std::convert::{TryFrom, TryInto};

use super::{Decoder, Encoder};

/// Adapter trait: convert to/from an owned byte container using Encoder/Decoder.
pub trait ByteParser<P> {
    /// Byte container definition
    /// Must be constructible and mutable as bytes for encoding,
    type Bytes: AsRef<[u8]>;

    /// Expected size of the byte container
    const EXPECTED_LEN: Option<usize> = None;

    /// Decode from an owned byte container with params.
    fn from_bytes_with(bytes: &[u8], params: P) -> Result<Self, std::io::Error>
    where
        Self: Sized + Decoder<P>,
    {
        if let Some(n) = Self::EXPECTED_LEN {
            if bytes.len() != n {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected {} bytes, got {}", n, bytes.len()),
                ));
            }
        }

        let mut rdr: &[u8] = bytes;
        Self::decode(&mut rdr, params)
    }

    /// Encode into an owned byte container with params.
    fn to_bytes_with(&self, params: P) -> Result<Self::Bytes, std::io::Error>
    where
        Self: Encoder<P>,
        Self::Bytes: TryFrom<Vec<u8>>,
    {
        let mut v = Vec::new();
        self.encode(&mut v, params)?;

        if let Some(exp) = Self::EXPECTED_LEN {
            if v.len() != exp {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "encoded size mismatch: expected {} bytes, got {}",
                        exp,
                        v.len()
                    ),
                ));
            }
        }

        // Now do the actual conversion; map any error to io::Error
        Self::Bytes::try_from(v).map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to encode structure to bytes",
            )
        })
    }

    /// Helper from_bytes Function in case no parameters are needed
    fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error>
    where
        Self: Sized + Decoder<()>,
    {
        if let Some(n) = Self::EXPECTED_LEN {
            if bytes.len() != n {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected {} bytes, got {}", n, bytes.len()),
                ));
            }
        }

        let mut rdr: &[u8] = bytes;
        Self::decode(&mut rdr, ())
    }

    /// Helper to_bytes function in case no parameters are needed
    fn to_bytes(&self) -> Result<Self::Bytes, std::io::Error>
    where
        Self: Encoder<()>,
        Self::Bytes: TryFrom<Vec<u8>>,
    {
        let mut v = Vec::new();
        self.encode(&mut v, ())?;

        if let Some(exp) = Self::EXPECTED_LEN {
            if v.len() != exp {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "encoded size mismatch: expected {} bytes, got {}",
                        exp,
                        v.len()
                    ),
                ));
            }
        }

        // Now do the actual conversion; map any error to io::Error
        Self::Bytes::try_from(v).map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to encode structure to bytes",
            )
        })
    }
}

impl<const N: usize> ByteParser<()> for [u8; N] {
    type Bytes = [u8; N];
    const EXPECTED_LEN: Option<usize> = Some(N);

    fn from_bytes(slice: &[u8]) -> std::io::Result<Self> {
        let arr: [u8; N] = slice.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "length mismatch")
        })?;
        Ok(arr)
    }

    fn to_bytes(&self) -> std::io::Result<Self::Bytes> {
        Ok(*self)
    }
}

impl ByteParser<()> for Vec<u8> {
    type Bytes = Vec<u8>;

    fn from_bytes(slice: &[u8]) -> std::io::Result<Self> {
        Ok(slice.to_vec())
    }

    fn to_bytes(&self) -> std::io::Result<Self::Bytes> {
        Ok(self.clone())
    }
}

macro_rules! impl_byte_parser_types
{
    ($($t:ty), *) => {
        $(
            impl ByteParser<()> for $t {
                type Bytes = [u8; std::mem::size_of::<$t>()];
            }
        )*
    };
}

impl_byte_parser_types!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

#[cfg(test)]
mod tests {
    use super::*;

    // Array tests
    #[test]
    fn test_array_conversions() {
        let arr: [u8; 4] = [1, 2, 3, 4];
        assert_eq!(arr.to_bytes().unwrap(), [1, 2, 3, 4]);
        assert_eq!(<[u8; 4]>::from_bytes(&[1, 2, 3, 4]).unwrap(), [1, 2, 3, 4]);
    }

    // Numeric type tests
    #[test]
    fn test_u8_conversions() {
        let val: u8 = 42;
        assert_eq!(val.to_bytes().unwrap(), [42]);
        assert_eq!(u8::from_bytes(&[42]).unwrap(), 42);
    }

    #[test]
    fn test_u16_conversions() {
        let val: u16 = 0x1234;
        assert_eq!(val.to_bytes().unwrap(), [0x34, 0x12]);
        assert_eq!(u16::from_bytes(&[0x34, 0x12]).unwrap(), 0x1234);
    }

    #[test]
    fn test_u32_conversions() {
        let val: u32 = 0x12345678;
        assert_eq!(val.to_bytes().unwrap(), [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(
            u32::from_bytes(&[0x78, 0x56, 0x34, 0x12]).unwrap(),
            0x12345678
        );
    }

    // Edge cases
    #[test]
    fn test_numeric_edge_cases() {
        assert_eq!(
            u8::from_bytes(&u8::MAX.to_bytes().unwrap()).unwrap(),
            u8::MAX
        );
        assert_eq!(
            u16::from_bytes(&u16::MAX.to_bytes().unwrap()).unwrap(),
            u16::MAX
        );
        assert_eq!(
            u32::from_bytes(&u32::MAX.to_bytes().unwrap()).unwrap(),
            u32::MAX
        );
        assert_eq!(
            i8::from_bytes(&i8::MIN.to_bytes().unwrap()).unwrap(),
            i8::MIN
        );
        assert_eq!(
            i16::from_bytes(&i16::MIN.to_bytes().unwrap()).unwrap(),
            i16::MIN
        );
        assert_eq!(
            i32::from_bytes(&i32::MIN.to_bytes().unwrap()).unwrap(),
            i32::MIN
        );
    }

    // Round-trip tests
    #[test]
    fn test_round_trip_conversions() {
        let values = [
            0i32,
            1,
            -1,
            i32::MAX,
            i32::MIN,
            42,
            -42,
            0x12345678,
            -0x12345678,
        ];

        for &val in &values {
            assert_eq!(i32::from_bytes(&val.to_bytes().unwrap()).unwrap(), val);
        }
    }

    #[test]
    fn test_array_operations() {
        let arr1: [u8; 1] = [1];
        let arr4: [u8; 4] = [1, 2, 3, 4];
        let arr8: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        assert_eq!(arr1.to_bytes().unwrap(), [1]);
        assert_eq!(arr4.to_bytes().unwrap(), [1, 2, 3, 4]);
        assert_eq!(arr8.to_bytes().unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);

        assert_eq!(
            <[u8; 8]>::from_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn test_unsigned_integers() {
        // u8
        assert_eq!(255u8.to_bytes().unwrap(), [255]);
        assert_eq!(u8::from_bytes(&[128]).unwrap(), 128);

        // u16
        assert_eq!(0xFF00u16.to_bytes().unwrap(), [0x00, 0xFF]);
        assert_eq!(u16::from_bytes(&[0x34, 0x12]).unwrap(), 0x1234);

        // u32
        assert_eq!(0x12345678u32.to_bytes().unwrap(), [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(
            u32::from_bytes(&[0x78, 0x56, 0x34, 0x12]).unwrap(),
            0x12345678
        );

        // u64
        assert_eq!(
            0x123456789ABCDEFu64.to_bytes().unwrap(),
            [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]
        );

        // u128
        assert_eq!(u128::MAX.to_bytes().unwrap()[15], 0xFF);
    }

    #[test]
    fn test_signed_integers() {
        // i8
        assert_eq!((-128i8).to_bytes().unwrap(), [0x80]);
        assert_eq!(i8::from_bytes(&[0x80]).unwrap(), -128);

        // i16
        assert_eq!((-32768i16).to_bytes().unwrap(), [0x00, 0x80]);
        assert_eq!(i16::from_bytes(&[0x00, 0x80]).unwrap(), -32768);

        // i32, i64, i128
        assert_eq!(i32::MIN.to_bytes().unwrap()[3], 0x80);
        assert_eq!(i64::MIN.to_bytes().unwrap()[7], 0x80);
        assert_eq!(i128::MIN.to_bytes().unwrap()[15], 0x80);
    }

    #[test]
    fn test_edge_cases() {
        // Max values
        assert_eq!(
            u8::from_bytes(&u8::MAX.to_bytes().unwrap()).unwrap(),
            u8::MAX
        );
        assert_eq!(
            u16::from_bytes(&u16::MAX.to_bytes().unwrap()).unwrap(),
            u16::MAX
        );
        assert_eq!(
            u32::from_bytes(&u32::MAX.to_bytes().unwrap()).unwrap(),
            u32::MAX
        );
        assert_eq!(
            u64::from_bytes(&u64::MAX.to_bytes().unwrap()).unwrap(),
            u64::MAX
        );
        assert_eq!(
            u128::from_bytes(&u128::MAX.to_bytes().unwrap()).unwrap(),
            u128::MAX
        );

        // Min values
        assert_eq!(
            i8::from_bytes(&i8::MIN.to_bytes().unwrap()).unwrap(),
            i8::MIN
        );
        assert_eq!(
            i16::from_bytes(&i16::MIN.to_bytes().unwrap()).unwrap(),
            i16::MIN
        );
        assert_eq!(
            i32::from_bytes(&i32::MIN.to_bytes().unwrap()).unwrap(),
            i32::MIN
        );
        assert_eq!(
            i64::from_bytes(&i64::MIN.to_bytes().unwrap()).unwrap(),
            i64::MIN
        );
        assert_eq!(
            i128::from_bytes(&i128::MIN.to_bytes().unwrap()).unwrap(),
            i128::MIN
        );
    }

    #[test]
    fn test_vec_byte_parser() {
        let vec = vec![10, 20, 30, 40];
        let bytes = vec.to_bytes().unwrap();
        assert_eq!(bytes, vec);

        let parsed = <Vec<u8> as ByteParser<()>>::from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(parsed, vec);
    }

    #[test]
    fn test_vec_byte_parser_clone_independence() {
        let vec = vec![1, 2, 3];
        let bytes = vec.to_bytes().unwrap();
        assert_eq!(vec, bytes);

        // Ensure modifying bytes doesn't affect the original vec
        let mut modified = bytes.clone();
        modified[0] = 99;
        assert_ne!(modified, vec);
    }
}
