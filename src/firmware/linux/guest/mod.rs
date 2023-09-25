// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
pub(crate) mod ioctl;
#[cfg(target_os = "linux")]
pub(crate) mod types;
