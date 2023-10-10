// SPDX-License-Identifier: Apache-2.0

//! Host FFI Wrappers for C Kernel APIs
#[cfg(target_os = "linux")]
pub(crate) mod ioctl;
pub(crate) mod types;
