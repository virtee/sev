// SPDX-License-Identifier: Apache-2.0

use super::ParseError;

/// Append encoded values to a byte buffer.
///
/// The value's type selects the [`Encoder`] implementation, so the caller does
/// not name it again.
pub trait ByteWrite {
    /// Encode `value` onto the end of this buffer.
    fn write_bytes<T, P>(&mut self, value: &T, params: P) -> Result<(), T::Error>
    where
        T: Encoder<P>;

    /// Append `n` zero bytes.
    ///
    /// This is the reserved padding that matches [`Cursor::skip_bytes`](crate::parser::Cursor::skip_bytes).
    /// Appending to a [`Vec`] cannot fail, so this returns the same buffer for chaining.
    fn skip_bytes(&mut self, n: usize) -> &mut Self;
}

impl ByteWrite for Vec<u8> {
    fn write_bytes<T, P>(&mut self, value: &T, params: P) -> Result<(), T::Error>
    where
        T: Encoder<P>,
    {
        value.encode(self, params)
    }

    fn skip_bytes(&mut self, n: usize) -> &mut Self {
        self.resize(self.len() + n, 0);
        self
    }
}

/// Encodes a value by appending bytes to a buffer.
///
/// `P` is extra context the value needs in order to encode, such as a CPU
/// generation. Use `()` when it needs none.
///
/// The [`parser` module](crate::parser#examples) shows a struct that implements
/// this trait together with [`Decoder`](crate::parser::Decoder).
pub trait Encoder<P> {
    /// Error returned when encoding fails.
    ///
    /// Byte-sized impls in this crate use [`ParseError`]. A type with its own
    /// failure modes can use another error that implements `From<ParseError>`.
    type Error;

    /// Append the encoding of `self` to `output`.
    fn encode(&self, output: &mut Vec<u8>, params: P) -> Result<(), Self::Error>;
}

impl<const N: usize> Encoder<()> for [u8; N] {
    type Error = ParseError;

    fn encode(&self, output: &mut Vec<u8>, _params: ()) -> Result<(), Self::Error> {
        output.extend_from_slice(self);
        Ok(())
    }
}

impl Encoder<()> for Vec<u8> {
    type Error = ParseError;

    fn encode(&self, output: &mut Vec<u8>, _params: ()) -> Result<(), Self::Error> {
        output.extend_from_slice(self);
        Ok(())
    }
}

macro_rules! impl_encoder {
    ($($t:ty),*) => {
        $(
            impl Encoder<()> for $t {
                type Error = ParseError;

                fn encode(&self, output: &mut Vec<u8>, _params: ()) -> Result<(), Self::Error> {
                    output.extend_from_slice(&self.to_le_bytes());
                    Ok(())
                }
            }
        )*
    };
}

impl_encoder!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_bytes_appends_zeros() {
        let mut output = vec![0x34, 0x12];
        output.skip_bytes(2).write_bytes(&0xAABBu16, ()).unwrap();
        assert_eq!(output, [0x34, 0x12, 0x00, 0x00, 0xBB, 0xAA]);
    }
}
