// SPDX-License-Identifier: Apache-2.0

use super::{Cursor, ParseError};

/// Decodes a value from a [`Cursor`] with the given parameters.
///
/// `P` is extra context the value needs in order to decode, such as a CPU
/// generation. Use `()` when it needs none.
///
/// The [`parser` module](crate::parser#examples) shows a struct that implements
/// this trait together with [`Encoder`](crate::parser::Encoder).
pub trait Decoder<P>: Sized {
    /// Error returned when decoding fails.
    ///
    /// Byte-sized impls in this crate use [`ParseError`]. A type with its own
    /// failure modes can use another error that implements `From<ParseError>`.
    type Error;

    /// Length of the whole value, when it is fixed.
    ///
    /// [`ByteParser`](crate::parser::ByteParser) rejects a buffer of any other
    /// length. Leave this as `None` when the length depends on the contents.
    const LEN: Option<usize> = None;

    /// Decode `Self` from `input`, advancing the cursor past the bytes consumed.
    fn decode(input: &mut Cursor<'_>, params: P) -> Result<Self, Self::Error>;
}

impl<const N: usize> Decoder<()> for [u8; N] {
    type Error = ParseError;
    const LEN: Option<usize> = Some(N);

    fn decode(input: &mut Cursor<'_>, _params: ()) -> Result<Self, Self::Error> {
        let mut buf = [0u8; N];
        buf.copy_from_slice(input.take(N)?);
        Ok(buf)
    }
}

/// Consumes every byte still in the cursor.
///
/// A `Vec<u8>` field in the middle of a larger structure would take the bytes
/// that belong to the fields after it. Prefer `[u8; N]` when the length is fixed.
impl Decoder<()> for Vec<u8> {
    type Error = ParseError;

    fn decode(input: &mut Cursor<'_>, _params: ()) -> Result<Self, Self::Error> {
        let remaining = input.remaining();
        let rest = input.take(remaining)?;
        Ok(rest.to_vec())
    }
}

macro_rules! impl_decoder {
    ($($t:ty),*) => {
        $(
            impl Decoder<()> for $t {
                type Error = ParseError;
                const LEN: Option<usize> = Some(std::mem::size_of::<$t>());

                #[inline]
                fn decode(input: &mut Cursor<'_>, _params: ()) -> Result<Self, Self::Error> {
                    const N: usize = std::mem::size_of::<$t>();
                    let mut buf = [0u8; N];
                    buf.copy_from_slice(input.take(N)?);
                    Ok(<$t>::from_le_bytes(buf))
                }
            }
        )*
    };
}

impl_decoder!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

#[cfg(test)]
mod tests {
    use super::super::Encoder;
    use super::*;

    fn encode_to_vec<T: Encoder<(), Error = ParseError>>(value: &T) -> Vec<u8> {
        let mut out = Vec::new();
        value.encode(&mut out, ()).expect("encode");
        out
    }

    fn decode_from_slice<T: Decoder<(), Error = ParseError>>(bytes: &[u8]) -> T {
        let mut input = Cursor::new(bytes);
        T::decode(&mut input, ()).expect("decode")
    }

    #[test]
    fn array_n_encode_decode_exact() {
        const N: usize = 8;
        let orig: [u8; N] = [1, 2, 3, 4, 5, 6, 7, 8];

        let enc = encode_to_vec(&orig);
        assert_eq!(enc, orig);

        let dec: [u8; N] = decode_from_slice(&enc);
        assert_eq!(dec, orig);
    }

    #[test]
    fn array_n_decode_short_errors() {
        const N: usize = 8;
        let short = [0u8; N - 1];
        let mut input = Cursor::new(&short);

        let err = <[u8; N] as Decoder<()>>::decode(&mut input, ()).unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEof { needed: N });
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn vec_u8_encode_decode_reads_to_end() {
        let data = b"hello world".to_vec();
        let enc = encode_to_vec(&data);
        assert_eq!(enc, data);

        let mut input = Cursor::new(&enc);
        let dec: Vec<u8> = Vec::<u8>::decode(&mut input, ()).expect("decode vec");
        assert_eq!(dec, data);
        assert!(input.is_empty());
    }

    #[test]
    fn u32_le_encode_decode_and_bytes() {
        let value: u32 = 0x0102_0304;
        let enc = encode_to_vec(&value);
        assert_eq!(enc, value.to_le_bytes());

        let dec: u32 = decode_from_slice(&enc);
        assert_eq!(dec, value);
    }

    macro_rules! roundtrip_int {
        ($name:ident, $t:ty, $val:expr) => {
            #[test]
            fn $name() {
                let value: $t = $val;
                let enc = encode_to_vec(&value);
                assert_eq!(enc, value.to_le_bytes());

                let dec: $t = decode_from_slice(&enc);
                assert_eq!(dec, value);
            }
        };
    }

    roundtrip_int!(rt_u8, u8, 0xAB);
    roundtrip_int!(rt_i8, i8, -5);
    roundtrip_int!(rt_u16, u16, 0xA1B2);
    roundtrip_int!(rt_i16, i16, -12345);
    roundtrip_int!(rt_u32, u32, 0xDEADBEEF);
    roundtrip_int!(rt_i32, i32, -0x0123_4567);
    roundtrip_int!(rt_u64, u64, 0x0123_4567_89AB_CDEF);
    roundtrip_int!(rt_i64, i64, -0x0123_4567_89AB_CDEF);
    roundtrip_int!(rt_u128, u128, 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210);
    roundtrip_int!(rt_i128, i128, -0x1234_5678_9ABC_DEF0_i128);

    #[test]
    fn sequential_decode_from_one_cursor() {
        let a: u16 = 0x1122;
        let b: u16 = 0xA1B2;
        let mut stream = Vec::new();
        a.encode(&mut stream, ()).unwrap();
        b.encode(&mut stream, ()).unwrap();

        let mut input = Cursor::new(&stream);
        let a2: u16 = Decoder::decode(&mut input, ()).unwrap();
        let b2: u16 = Decoder::decode(&mut input, ()).unwrap();

        assert_eq!(a2, a);
        assert_eq!(b2, b);
        assert!(input.is_empty());
    }

    #[test]
    fn vec_decode_reads_remaining_only() {
        let prefix = [0xFFu8; 3];
        let tail = b"tail".to_vec();
        let mut combined = Vec::new();
        combined.extend_from_slice(&prefix);
        combined.extend_from_slice(&tail);

        let mut input = Cursor::new(&combined);
        input.take(prefix.len()).unwrap();

        let dec: Vec<u8> = Vec::<u8>::decode(&mut input, ()).unwrap();
        assert_eq!(dec, tail);
        assert!(input.is_empty());
    }
}
