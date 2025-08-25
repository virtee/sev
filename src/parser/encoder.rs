// SPDX-License-Identifier: Apache-2.0
use crate::util::array::*;
use std::io::Write;
/// Trait used to express encoding relationships.
pub trait Encoder<T> {
    /// Encodes the object to raw bytes.
    fn encode(&self, writer: &mut impl Write, params: T) -> Result<(), std::io::Error>;
}

impl<const N: usize> Encoder<()> for [u8; N] {
    fn encode(&self, writer: &mut impl Write, _params: ()) -> Result<(), std::io::Error> {
        writer.write_all(self)?;
        Ok(())
    }
}

impl Encoder<()> for Vec<u8> {
    fn encode(&self, writer: &mut impl Write, _params: ()) -> Result<(), std::io::Error> {
        writer.write_all(self)?;
        Ok(())
    }
}

impl<const N: usize> Encoder<()> for Array<u8, N> {
    fn encode(&self, writer: &mut impl Write, _params: ()) -> Result<(), std::io::Error> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

macro_rules! impl_encoder {
    ($($t:ty), *) => {
        $(
            impl Encoder<()> for $t {

                fn encode(&self, writer: &mut impl Write, _params: ()) -> Result<(), std::io::Error> {
                    let bytes = self.to_le_bytes();
                    writer.write_all(&bytes)?;
                    Ok(())
                }
            }
        )*
    };
}

impl_encoder!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);
