// SPDX-License-Identifier: Apache-2.0

//! Host FFI Wrappers for C Kernel APIs
pub(crate) mod ioctl;
pub(crate) mod types;

// Linux x86 standard page sizes are 4096 bytes.
pub(crate) const _4K_PAGE: usize = 4096;
