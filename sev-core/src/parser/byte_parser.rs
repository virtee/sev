// SPDX-License-Identifier: Apache-2.0

use super::{Cursor, Decoder, Encoder, ParseError};

/// Whole-buffer helpers over [`Decoder`] and [`Encoder`].
///
/// `decode` and `encode` walk fields inside an implementation. `from_bytes` and
/// `to_bytes` are the calls a user makes when the buffer is one complete value.
/// Any type that implements [`Decoder`] gets this trait automatically.
pub trait ByteParser<P>: Sized {
    /// Decode one value from `bytes`.
    ///
    /// When [`Decoder::LEN`] is `Some`, `bytes` must be that long.
    fn from_bytes_with<E>(bytes: &[u8], params: P) -> Result<Self, E>
    where
        Self: Decoder<P, Error = E>,
        E: From<ParseError>,
    {
        ensure_len(<Self as Decoder<P>>::LEN, bytes.len())?;
        let mut input = Cursor::new(bytes);
        Self::decode(&mut input, params)
    }

    /// Encode one value.
    ///
    /// When [`Decoder::LEN`] is `Some`, the encoded buffer must be that long.
    fn to_bytes_with<E>(&self, params: P) -> Result<Vec<u8>, E>
    where
        Self: Decoder<P, Error = E> + Encoder<P, Error = E>,
        E: From<ParseError>,
    {
        let mut encoded = Vec::new();
        self.encode(&mut encoded, params)?;
        ensure_encoded_len(<Self as Decoder<P>>::LEN, encoded.len())?;
        Ok(encoded)
    }

    /// [`from_bytes_with`](Self::from_bytes_with) for a value that takes no parameters.
    fn from_bytes<E>(bytes: &[u8]) -> Result<Self, E>
    where
        Self: Decoder<(), Error = E>,
        E: From<ParseError>,
    {
        ensure_len(<Self as Decoder<()>>::LEN, bytes.len())?;
        let mut input = Cursor::new(bytes);
        <Self as Decoder<()>>::decode(&mut input, ())
    }

    /// [`to_bytes_with`](Self::to_bytes_with) for a value that takes no parameters.
    fn to_bytes<E>(&self) -> Result<Vec<u8>, E>
    where
        Self: Decoder<(), Error = E> + Encoder<(), Error = E>,
        E: From<ParseError>,
    {
        let mut encoded = Vec::new();
        <Self as Encoder<()>>::encode(self, &mut encoded, ())?;
        ensure_encoded_len(<Self as Decoder<()>>::LEN, encoded.len())?;
        Ok(encoded)
    }
}

impl<T, P> ByteParser<P> for T where T: Decoder<P> {}

fn ensure_len<E>(expected: Option<usize>, actual: usize) -> Result<(), E>
where
    E: From<ParseError>,
{
    match expected {
        Some(expected) if expected != actual => {
            Err(ParseError::LengthMismatch { expected, actual }.into())
        }
        _ => Ok(()),
    }
}

fn ensure_encoded_len<E>(expected: Option<usize>, actual: usize) -> Result<(), E>
where
    E: From<ParseError>,
{
    match expected {
        Some(expected) if expected != actual => {
            Err(ParseError::EncodeLength { expected, actual }.into())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_hides_the_cursor() {
        let value: u16 = 0x1234;
        let bytes = value.to_bytes().unwrap();
        assert_eq!(bytes, [0x34, 0x12]);
        assert_eq!(u16::from_bytes(&bytes).unwrap(), value);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        let err = u16::from_bytes(&[0x34]).unwrap_err();
        assert_eq!(
            err,
            ParseError::LengthMismatch {
                expected: 2,
                actual: 1
            }
        );
    }
}
