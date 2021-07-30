// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

pub trait FromLe: Sized {
    fn from_le(value: &[u8]) -> Result<Self>;
}

pub trait AsLeBytes<T> {
    fn as_le_bytes(&self) -> T;
}

impl FromLe for openssl::bn::BigNum {
    #[inline]
    fn from_le(value: &[u8]) -> Result<Self> {
        Ok(Self::from_slice(
            &value.iter().rev().cloned().collect::<Vec<_>>(),
        )?)
    }
}

impl AsLeBytes<[u8; 72]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 72] {
        let mut buf = [0u8; 72];

        for (i, b) in self.to_vec().iter().rev().cloned().enumerate() {
            buf[i] = b;
        }

        buf
    }
}

impl AsLeBytes<[u8; 512]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 512] {
        let mut buf = [0u8; 512];

        for (i, b) in self.to_vec().iter().rev().cloned().enumerate() {
            buf[i] = b;
        }

        buf
    }
}
