// SPDX-License-Identifier: Apache-2.0

pub mod host;

#[cfg(feature = "snp")]
pub mod guest;

pub(crate) const _4K_PAGE: usize = 4096;
