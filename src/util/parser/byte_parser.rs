// SPDX-License-Identifier: Apache-2.0

pub trait ByteParser {
    type Bytes: AsRef<[u8]>;

    fn from_bytes(bytes: Self::Bytes) -> Self;

    fn to_bytes(&self) -> Self::Bytes;

    fn default() -> Self;
}

impl<const N: usize> ByteParser for [u8; N] {
    type Bytes = [u8; N];

    #[inline(always)]
    fn from_bytes(bytes: Self::Bytes) -> Self {
        bytes
    }
    #[inline(always)]
    fn to_bytes(&self) -> Self::Bytes {
        *self
    }
    #[inline(always)]
    fn default() -> Self {
        [0u8; N]
    }
}

macro_rules! impl_byte_parser
{
    ($($t:ty), *) => {
        $(
            impl ByteParser for $t {
                type Bytes = [u8; std::mem::size_of::<$t>()];
                #[inline(always)]
                fn from_bytes(bytes: Self::Bytes) -> Self {
                    <$t>::from_le_bytes(bytes)
                }
                #[inline(always)]
                fn to_bytes(&self) -> Self::Bytes {
                    <$t>::to_le_bytes(*self)
                }
                #[inline(always)]
                fn default() -> Self {
                    0
                }
            }
        )*
    };
}

impl_byte_parser!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

#[cfg(test)]
mod tests {
    use super::*;

    // Array tests
    #[test]
    fn test_array_conversions() {
        let arr: [u8; 4] = [1, 2, 3, 4];
        assert_eq!(arr.to_bytes(), [1, 2, 3, 4]);
        assert_eq!(<[u8; 4]>::from_bytes([1, 2, 3, 4]), [1, 2, 3, 4]);
        assert_eq!(<[u8; 4] as ByteParser>::default(), [0, 0, 0, 0]);
    }

    // Numeric type tests
    #[test]
    fn test_u8_conversions() {
        let val: u8 = 42;
        assert_eq!(val.to_bytes(), [42]);
        assert_eq!(u8::from_bytes([42]), 42);
        assert_eq!(<u8 as ByteParser>::default(), 0);
    }

    #[test]
    fn test_u16_conversions() {
        let val: u16 = 0x1234;
        assert_eq!(val.to_bytes(), [0x34, 0x12]);
        assert_eq!(u16::from_bytes([0x34, 0x12]), 0x1234);
        assert_eq!(<u16 as ByteParser>::default(), 0);
    }

    #[test]
    fn test_u32_conversions() {
        let val: u32 = 0x12345678;
        assert_eq!(val.to_bytes(), [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(u32::from_bytes([0x78, 0x56, 0x34, 0x12]), 0x12345678);
        assert_eq!(<u32 as ByteParser>::default(), 0);
    }

    // Edge cases
    #[test]
    fn test_numeric_edge_cases() {
        assert_eq!(u8::from_bytes(u8::MAX.to_bytes()), u8::MAX);
        assert_eq!(u16::from_bytes(u16::MAX.to_bytes()), u16::MAX);
        assert_eq!(u32::from_bytes(u32::MAX.to_bytes()), u32::MAX);
        assert_eq!(i8::from_bytes(i8::MIN.to_bytes()), i8::MIN);
        assert_eq!(i16::from_bytes(i16::MIN.to_bytes()), i16::MIN);
        assert_eq!(i32::from_bytes(i32::MIN.to_bytes()), i32::MIN);
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
            assert_eq!(i32::from_bytes(val.to_bytes()), val);
        }
    }

    #[test]
    fn test_array_operations() {
        let arr1: [u8; 1] = [1];
        let arr4: [u8; 4] = [1, 2, 3, 4];
        let arr8: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        assert_eq!(arr1.to_bytes(), [1]);
        assert_eq!(arr4.to_bytes(), [1, 2, 3, 4]);
        assert_eq!(arr8.to_bytes(), [1, 2, 3, 4, 5, 6, 7, 8]);

        assert_eq!(<[u8; 4] as ByteParser>::default(), [0; 4]);
        assert_eq!(
            <[u8; 8]>::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn test_unsigned_integers() {
        // u8
        assert_eq!(255u8.to_bytes(), [255]);
        assert_eq!(u8::from_bytes([128]), 128);
        assert_eq!(<u8 as ByteParser>::default(), 0);

        // u16
        assert_eq!(0xFF00u16.to_bytes(), [0x00, 0xFF]);
        assert_eq!(u16::from_bytes([0x34, 0x12]), 0x1234);
        assert_eq!(<u16 as ByteParser>::default(), 0);

        // u32
        assert_eq!(0x12345678u32.to_bytes(), [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(u32::from_bytes([0x78, 0x56, 0x34, 0x12]), 0x12345678);
        assert_eq!(<u32 as ByteParser>::default(), 0);

        // u64
        assert_eq!(
            0x123456789ABCDEFu64.to_bytes(),
            [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]
        );
        assert_eq!(<u64 as ByteParser>::default(), 0);

        // u128
        assert_eq!(u128::MAX.to_bytes()[15], 0xFF);
        assert_eq!(<u128 as ByteParser>::default(), 0);
    }

    #[test]
    fn test_signed_integers() {
        // i8
        assert_eq!((-128i8).to_bytes(), [0x80]);
        assert_eq!(i8::from_bytes([0x80]), -128);
        assert_eq!(<i8 as ByteParser>::default(), 0);

        // i16
        assert_eq!((-32768i16).to_bytes(), [0x00, 0x80]);
        assert_eq!(i16::from_bytes([0x00, 0x80]), -32768);
        assert_eq!(<i16 as ByteParser>::default(), 0);

        // i32, i64, i128
        assert_eq!(i32::MIN.to_bytes()[3], 0x80);
        assert_eq!(i64::MIN.to_bytes()[7], 0x80);
        assert_eq!(i128::MIN.to_bytes()[15], 0x80);
    }

    #[test]
    fn test_edge_cases() {
        // Size-specific tests
        assert_eq!(<usize as ByteParser>::default(), 0);
        assert_eq!(<isize as ByteParser>::default(), 0);

        // Max values
        assert_eq!(u8::from_bytes(u8::MAX.to_bytes()), u8::MAX);
        assert_eq!(u16::from_bytes(u16::MAX.to_bytes()), u16::MAX);
        assert_eq!(u32::from_bytes(u32::MAX.to_bytes()), u32::MAX);
        assert_eq!(u64::from_bytes(u64::MAX.to_bytes()), u64::MAX);
        assert_eq!(u128::from_bytes(u128::MAX.to_bytes()), u128::MAX);

        // Min values
        assert_eq!(i8::from_bytes(i8::MIN.to_bytes()), i8::MIN);
        assert_eq!(i16::from_bytes(i16::MIN.to_bytes()), i16::MIN);
        assert_eq!(i32::from_bytes(i32::MIN.to_bytes()), i32::MIN);
        assert_eq!(i64::from_bytes(i64::MIN.to_bytes()), i64::MIN);
        assert_eq!(i128::from_bytes(i128::MIN.to_bytes()), i128::MIN);
    }
}
