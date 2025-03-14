// SPDX-License-Identifier: Apache-2.0

//! Helpful structure to deal with arrays with a size larger than  32 bytes

use crate::error::ArrayError;

#[cfg(feature = "snp")]
use crate::util::parser::ByteParser;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, LowerHex, UpperHex},
    ops::{Deref, DerefMut},
};

/// Large array structure to serialize and default arrays larger than 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Array<T, const N: usize>(#[serde(with = "BigArray")] pub [T; N])
where
    T: Serialize + for<'a> Deserialize<'a>;

impl<T, const N: usize> LowerHex for Array<T, N>
where
    T: std::marker::Copy
        + std::default::Default
        + for<'a> Deserialize<'a>
        + Serialize
        + Debug
        + LowerHex,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<T, const N: usize> UpperHex for Array<T, N>
where
    T: std::marker::Copy
        + std::default::Default
        + for<'a> Deserialize<'a>
        + Serialize
        + Debug
        + UpperHex,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl<T, const N: usize> std::fmt::Display for Array<T, N>
where
    T: std::marker::Copy
        + std::default::Default
        + for<'a> Deserialize<'a>
        + Serialize
        + Debug
        + UpperHex,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f)?;
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 && i % 16 == 0 {
                writeln!(f)?;
            } else if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "snp")]
impl<const N: usize> ByteParser for Array<u8, N> {
    type Bytes = [u8; N];

    #[inline]
    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self(bytes)
    }

    #[inline]
    fn to_bytes(&self) -> Self::Bytes {
        self.0
    }

    #[inline]
    fn default() -> Self {
        Self([0; N])
    }
}

impl<T, const N: usize> Default for Array<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    fn default() -> Self {
        Self([T::default(); N])
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for Array<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    type Error = ArrayError;

    fn try_from(vec: Vec<T>) -> Result<Self, Self::Error> {
        Ok(Array(vec.try_into().map_err(|_| {
            ArrayError::VectorError("Vector is the wrong size".to_string())
        })?))
    }
}

impl<T, const N: usize> TryFrom<[T; N]> for Array<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    type Error = ArrayError;

    fn try_from(array: [T; N]) -> Result<Self, Self::Error> {
        Ok(Array(array))
    }
}

impl<T, const N: usize> TryFrom<&[T]> for Array<T, N>
where
    T: std::marker::Copy
        + std::default::Default
        + for<'a> Deserialize<'a>
        + Serialize
        + Debug
        + LowerHex,
{
    type Error = ArrayError;

    fn try_from(slice: &[T]) -> Result<Self, Self::Error> {
        Ok(Array(slice.try_into()?))
    }
}

impl<T, const N: usize> AsRef<[T]> for Array<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<T, const N: usize> AsMut<[T]> for Array<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.0.as_mut()
    }
}

impl<T, const N: usize> Deref for Array<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    type Target = [T; N];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const N: usize> DerefMut for Array<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
