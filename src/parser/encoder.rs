// SPDX-License-Identifier: Apache-2.0

//! Serialize firmware ABI types into byte streams.
//!
//! [`Encoder`] is the write-side primitive. Complex types in [`crate::types`]
//! implement `encode` by writing fields sequentially in firmware-defined order.
//!
//! # Context parameter
//!
//! Pass `()` for fixed layouts. Pass [`Generation`](crate::types::shared::Generation),
//! [`FirmwareVersion`](crate::types::shared::FirmwareVersion), or
//! another context type when field width or reserved-bit handling depends on
//! platform or firmware revision.
//!
//! # Primitive impls
//!
//! Integers encode as little-endian fixed-width bytes. `[u8; N]` and [`Vec<u8>`]
//! write raw bytes unchanged.

use std::io::Write;

/// Write a value to a byte stream in firmware wire format.
///
/// The type parameter `T` carries layout context (see module docs). Implementors
/// under [`crate::types`] write fields in the order defined by the AMD firmware
/// specification.
///
/// # Example
///
/// ```ignore
/// let mut buf = Vec::new();
/// value.encode(&mut buf, Generation::Turin)?;
/// ```
pub trait Encoder<T> {
    /// Serialize `self` into `writer` using `params` for context-dependent layouts.
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
