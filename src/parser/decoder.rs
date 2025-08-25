// SPDX-License-Identifier: Apache-2.0

use crate::util::array::*;
use std::io::Read;
/// Trait used to express decoding relationships.
pub trait Decoder<T>: Sized {
    /// Decodes from the reader with the given parameters.
    fn decode(reader: &mut impl Read, params: T) -> Result<Self, std::io::Error>;
}

impl<const N: usize> Decoder<()> for [u8; N] {
    fn decode(reader: &mut impl Read, _params: ()) -> Result<Self, std::io::Error> {
        let mut buf = [0u8; N];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl Decoder<()> for Vec<u8> {
    fn decode(reader: &mut impl Read, _params: ()) -> Result<Self, std::io::Error> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    }
}

impl<const N: usize> Decoder<()> for Array<u8, N> {
    fn decode(reader: &mut impl Read, _params: ()) -> Result<Self, std::io::Error> {
        let mut buf = [0u8; N];
        reader.read_exact(&mut buf)?;
        Ok(Array(buf))
    }
}

macro_rules! impl_decoder
{
    ($($t:ty), *) => {
        $(
            impl Decoder<()> for $t {
                #[inline(always)]
                fn decode(reader: &mut impl Read, _params: ()) -> Result<Self, std::io::Error> {
                    let mut buf = [0u8; std::mem::size_of::<$t>()];
                    reader.read_exact(&mut buf)?;
                    Ok(<$t>::from_le_bytes(buf))
                }
            }
        )*
    };
}

impl_decoder!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

// Tests for both Encoder and Decoder
#[cfg(test)]
mod tests {
    use super::super::Encoder;
    use super::*;
    use std::io::{Cursor, Read};

    fn encode_to_vec<T: Encoder<()>>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        v.encode(&mut out, ()).expect("encode");
        out
    }

    fn decode_from_slice<T: Decoder<()>>(bytes: &[u8]) -> T {
        let mut rdr: &[u8] = bytes;
        T::decode(&mut rdr, ()).expect("decode")
    }

    #[test]
    fn array_n_encode_decode_exact() {
        const N: usize = 8;
        let orig: [u8; N] = [1, 2, 3, 4, 5, 6, 7, 8];

        // encode
        let enc = encode_to_vec(&orig);
        assert_eq!(enc, orig);

        // decode
        let dec: [u8; N] = decode_from_slice(&enc);
        assert_eq!(dec, orig);
    }

    #[test]
    fn array_n_decode_short_errors() {
        const N: usize = 8;
        let short = [0u8; N - 1];
        let mut rdr: &[u8] = &short;

        let err = <[u8; N] as Decoder<()>>::decode(&mut rdr, ()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn vec_u8_encode_decode_reads_to_end() {
        // Vec<u8> decode reads to end; add trailing data and ensure it's all consumed
        let data = b"hello world".to_vec();
        let enc = encode_to_vec(&data);
        assert_eq!(enc, data);

        let mut rdr = Cursor::new(enc.clone());
        let dec: Vec<u8> = Vec::<u8>::decode(&mut rdr, ()).expect("decode vec");
        assert_eq!(dec, data);

        // After reading to end, further reads should be EOF
        let mut extra = [0u8; 1];
        let n = rdr.read(&mut extra).expect("read after end");
        assert_eq!(n, 0);
    }

    #[test]
    fn array_wrapper_encode_decode() {
        const N: usize = 16;
        let orig_inner: [u8; N] = *b"0123456789ABCDEF";
        let orig = Array(orig_inner);

        let enc = encode_to_vec(&orig);
        assert_eq!(enc, orig_inner);

        let dec: Array<u8, N> = decode_from_slice(&enc);
        assert_eq!(dec.0, orig_inner);
    }

    #[test]
    fn array_wrapper_decode_short_errors() {
        const N: usize = 16;
        let short = [0u8; N - 2];
        let mut rdr: &[u8] = &short;

        let err = <Array<u8, N> as Decoder<()>>::decode(&mut rdr, ()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn u32_le_encode_decode_and_bytes() {
        let v: u32 = 0x0102_0304;
        let enc = encode_to_vec(&v);
        // little-endian bytes
        assert_eq!(enc, v.to_le_bytes());

        // decode back
        let dec: u32 = decode_from_slice(&enc);
        assert_eq!(dec, v);
    }

    macro_rules! roundtrip_int {
        ($name:ident, $t:ty, $val:expr) => {
            #[test]
            fn $name() {
                let v: $t = $val;
                // encode -> verify bytes == to_le_bytes()
                let enc = encode_to_vec(&v);
                assert_eq!(enc, v.to_le_bytes());

                // decode -> equals original
                let dec: $t = decode_from_slice(&enc);
                assert_eq!(dec, v);
            }
        };
    }

    // Test a representative value for each type
    roundtrip_int!(rt_u8, u8, 0xAB);
    roundtrip_int!(rt_i8, i8, -5);
    roundtrip_int!(rt_u16, u16, 0xA1B2);
    roundtrip_int!(rt_i16, i16, -12345);
    roundtrip_int!(rt_u32, u32, 0xDEADBEEF);
    roundtrip_int!(rt_i32, i32, -0x0123_45677);
    roundtrip_int!(rt_u64, u64, 0x0123_4567_89AB_CDEF);
    roundtrip_int!(rt_i64, i64, -0x0123_4567_89AB_CDEF);
    roundtrip_int!(rt_u128, u128, 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210);
    roundtrip_int!(rt_i128, i128, -0x1234_5678_9ABC_DEF0_i128);
    // For usize/isize, value size is platform-dependent but to_le_bytes/from_le_bytes are fine
    roundtrip_int!(rt_usize, usize, 0x1234_5678usize);
    roundtrip_int!(rt_isize, isize, -0x0123_4567_isize);

    #[test]
    fn sequential_decode_from_stream() {
        // Two u16 values back-to-back
        let a: u16 = 0x1122;
        let b: u16 = 0xA1B2;
        let mut stream = Vec::new();
        a.encode(&mut stream, ()).unwrap();
        b.encode(&mut stream, ()).unwrap();

        let mut rdr = Cursor::new(stream);
        let a2: u16 = Decoder::decode(&mut rdr, ()).unwrap();
        let b2: u16 = Decoder::decode(&mut rdr, ()).unwrap();

        assert_eq!(a2, a);
        assert_eq!(b2, b);
        // EOF now
        let mut tmp = [0u8; 1];
        assert_eq!(rdr.read(&mut tmp).unwrap(), 0);
    }

    #[test]
    fn decode_array_from_cursor_direct() {
        const N: usize = 4;
        let bytes = [9u8, 8, 7, 6];
        let mut rdr = Cursor::new(bytes);
        let parsed: [u8; N] = <[u8; N] as Decoder<()>>::decode(&mut rdr, ()).unwrap();
        assert_eq!(parsed, bytes);
    }

    #[test]
    fn encode_array_into_writer_direct() {
        const N: usize = 4;
        let bytes = [1u8, 2, 3, 4];
        let mut out = Vec::new();
        <[u8; N] as Encoder<()>>::encode(&bytes, &mut out, ()).unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn vec_decode_reads_remaining_only() {
        // Prefix some data, then ensure Vec<u8>::decode picks up exactly what's left.
        let prefix = [0xFFu8; 3];
        let tail = b"tail".to_vec();
        let mut combined = Vec::new();
        combined.extend_from_slice(&prefix);
        combined.extend_from_slice(&tail);

        // Position reader after prefix
        let mut rdr = Cursor::new(combined);
        rdr.set_position(prefix.len() as u64);

        let dec: Vec<u8> = Vec::<u8>::decode(&mut rdr, ()).unwrap();
        assert_eq!(dec, tail);
    }
}
