// SPDX-License-Identifier: Apache-2.0

//! Helpful structure to deal with arrays with a size larger than  32 bytes

use crate::error::LargeArrayError;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::convert::{TryFrom, TryInto};

/// Large array structure to serialize and default arrays larger than 32 bytes.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[repr(C)]
pub struct LargeArray<T, const N: usize>(#[serde(with = "BigArray")] [T; N])
where
    T: for<'a> Deserialize<'a> + Serialize;

impl<T, const N: usize> Default for LargeArray<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    fn default() -> Self {
        Self([T::default(); N])
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for LargeArray<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    type Error = LargeArrayError;

    fn try_from(vec: Vec<T>) -> Result<Self, Self::Error> {
        Ok(LargeArray(vec.try_into().map_err(|_| {
            LargeArrayError::VectorError("Vector is the wrong size".to_string())
        })?))
    }
}

impl<T, const N: usize> TryFrom<[T; N]> for LargeArray<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    type Error = LargeArrayError;

    fn try_from(array: [T; N]) -> Result<Self, Self::Error> {
        Ok(LargeArray(array))
    }
}

impl<T, const N: usize> TryFrom<&[T]> for LargeArray<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    type Error = LargeArrayError;

    fn try_from(slice: &[T]) -> Result<Self, Self::Error> {
        Ok(LargeArray(slice.try_into()?))
    }
}

impl<T, const N: usize> LargeArray<T, N>
where
    T: std::marker::Copy + std::default::Default + for<'a> Deserialize<'a> + Serialize,
{
    /// Get the large array as a regular array format
    pub fn as_array(&self) -> [T; N] {
        self.0
    }

    /// Get the large array as a slice
    pub fn as_slice(&self) -> &[T; N] {
        &self.0
    }

    /// Get the large array as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [T; N] {
        &mut self.0
    }
}
